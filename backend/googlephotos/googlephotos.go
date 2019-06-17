// Package googlephotos provides an interface to Google Photos
package googlephotos

/*

For duplicates, prefix the file name with {theID} then can find those easily

FIXME album names could have / in
FIXME image names might have / in too ?

/upload directory can show all recent uploads?

Is creation date the time of upload or EXIF time or what?

IDs are base64 [A-Za-z0-9_-], shortest seen is 55 chars
[A-Za-z0-9_-]{55,}

*/

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ncw/rclone/backend/googlephotos/api"
	"github.com/ncw/rclone/fs"
	"github.com/ncw/rclone/fs/config"
	"github.com/ncw/rclone/fs/config/configmap"
	"github.com/ncw/rclone/fs/config/configstruct"
	"github.com/ncw/rclone/fs/config/obscure"
	"github.com/ncw/rclone/fs/fserrors"
	"github.com/ncw/rclone/fs/hash"
	"github.com/ncw/rclone/lib/oauthutil"
	"github.com/ncw/rclone/lib/pacer"
	"github.com/ncw/rclone/lib/rest"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	// NOTE: This API is deprecated
)

var (
	errFIXME      = errors.New("FIXME not implemented")
	errCantUpload = errors.New("can't upload files here")
)

const (
	rcloneClientID              = "202264815644-rt1o1c9evjaotbpbab10m83i8cnjk077.apps.googleusercontent.com"
	rcloneEncryptedClientSecret = "kLJLretPefBgrDHosdml_nlF64HZ9mUcO85X5rdjYBPP8ChA-jr3Ow"
	rootURL                     = "https://photoslibrary.googleapis.com/v1"
	listChunks                  = 100 // chunk size to read directory listings
	albumChunks                 = 50  // chunk size to read album listings
	minSleep                    = 10 * time.Millisecond
	maxSleep                    = 2 * time.Second
	decayConstant               = 2 // bigger for slower decay, exponential
)

var (
	// Description of how to auth for this app
	oauthConfig = &oauth2.Config{
		Scopes: []string{
			// https://www.googleapis.com/auth/photoslibrary.readonly
			"https://www.googleapis.com/auth/photoslibrary",
		},
		Endpoint:     google.Endpoint,
		ClientID:     rcloneClientID,
		ClientSecret: obscure.MustReveal(rcloneEncryptedClientSecret),
		RedirectURL:  oauthutil.TitleBarRedirectURL,
	}
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "google photos",
		Prefix:      "gphotos",
		Description: "Google Photos",
		NewFs:       NewFs,
		Config: func(name string, m configmap.Mapper) {
			err := oauthutil.Config("google photos", name, m, oauthConfig)
			if err != nil {
				log.Fatalf("Failed to configure token: %v", err)
			}
		},
		Options: []fs.Option{{
			Name: config.ConfigClientID,
			Help: "Google Application Client Id\nLeave blank normally.",
		}, {
			Name: config.ConfigClientSecret,
			Help: "Google Application Client Secret\nLeave blank normally.",
		}, {
			Name:    "read_size",
			Default: false,
			Help: `Set to read the size of media items.

Normally rclone does not read the size of media items since this takes
another transaction.  This isn't necessary for syncing.  However
rclone mount needs to know the size of files in advance of reading
them, so setting this flag when using rclone mount if recommended if
you want to read media.	`,
		}},
	})
}

// Options defines the configuration for this backend
type Options struct {
	ReadSize bool `config:"read_size"`
}

// Fs represents a remote storage server
type Fs struct {
	name      string           // name of this remote
	root      string           // the path we are working on if any
	opt       Options          // parsed options
	features  *fs.Features     // optional features
	srv       *rest.Client     // the connection to the one drive server
	pacer     *fs.Pacer        // To pace the API calls
	startTime time.Time        // time Fs was started - used for datestamps
	albums    map[bool]*albums // albums, shared or not
}

// All the albums
type albums struct {
	albums  []api.Album           // all the albums
	byID    map[string]*api.Album //..indexed by ID
	byTitle map[string]*api.Album //..indexed by Title
}

// Object describes a storage object
//
// Will definitely have info but maybe not meta
type Object struct {
	fs       *Fs       // what this object is part of
	remote   string    // The remote path
	url      string    // download path
	id       string    // ID of this object
	bytes    int64     // Bytes in the object
	modTime  time.Time // Modified time of the object
	mimeType string
}

// ------------------------------------------------------------

// Name of the remote (as passed into NewFs)
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String converts this Fs to a string
func (f *Fs) String() string {
	return fmt.Sprintf("Google Photos path %s", f.root)
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

// retryErrorCodes is a slice of error codes that we will retry
var retryErrorCodes = []int{
	429, // Too Many Requests.
	500, // Internal Server Error
	502, // Bad Gateway
	503, // Service Unavailable
	504, // Gateway Timeout
	509, // Bandwidth Limit Exceeded
}

// shouldRetry returns a boolean as to whether this resp and err
// deserve to be retried.  It returns the err as a convenience
func shouldRetry(resp *http.Response, err error) (bool, error) {
	return fserrors.ShouldRetry(err) || fserrors.ShouldRetryHTTP(resp, retryErrorCodes), err
}

// errorHandler parses a non 2xx error response into an error
func errorHandler(resp *http.Response) error {
	body, err := rest.ReadBody(resp)
	if err != nil {
		body = nil
	}
	var e = api.Error{
		Details: api.ErrorDetails{
			Code:    resp.StatusCode,
			Message: string(body),
			Status:  resp.Status,
		},
	}
	if body != nil {
		_ = json.Unmarshal(body, &e)
	}
	return &e
}

// NewFs constructs an Fs from the path, bucket:path
func NewFs(name, root string, m configmap.Mapper) (fs.Fs, error) {
	// Parse config into Options struct
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	oAuthClient, _, err := oauthutil.NewClient(name, m, oauthConfig)
	if err != nil {
		return nil, errors.Wrap(err, "failed to configure Box")
	}

	f := &Fs{
		name:      name,
		root:      strings.Trim(root, "/"),
		opt:       *opt,
		srv:       rest.NewClient(oAuthClient).SetRoot(rootURL),
		pacer:     fs.NewPacer(pacer.NewDefault(pacer.MinSleep(minSleep), pacer.MaxSleep(maxSleep), pacer.DecayConstant(decayConstant))),
		startTime: time.Now(),
		albums:    map[bool]*albums{},
	}
	f.features = (&fs.Features{
		ReadMimeType:  true,
		WriteMimeType: true,
	}).Fill(f)
	f.srv.SetErrorHandler(errorHandler)

	_, _, pattern := patterns.match(f.root, "")
	if pattern != nil && pattern.isFile {
		f.root, _ = path.Split(f.root)
		f.root = strings.Trim(f.root, "/")
		return f, fs.ErrorIsFile
	}

	return f, nil
}

// Return an Object from a path
//
// If it can't be found it returns the error fs.ErrorObjectNotFound.
func (f *Fs) newObjectWithInfo(remote string, info *api.MediaItem) (fs.Object, error) {
	o := &Object{
		fs:     f,
		remote: remote,
	}
	if info != nil {
		o.setMetaData(info)
	} else {
		err := o.readMetaData() // reads info and meta, returning an error
		if err != nil {
			return nil, err
		}
	}
	return o, nil
}

// NewObject finds the Object at remote.  If it can't be found
// it returns the error fs.ErrorObjectNotFound.
func (f *Fs) NewObject(remote string) (fs.Object, error) {
	return f.newObjectWithInfo(remote, nil)
}

// addID adds the ID to name
func addID(name string, ID string) string {
	idStr := "{" + ID + "}"
	if name == "" {
		return idStr
	}
	return name + " " + idStr
}

// addFileID adds the ID to the fileName passed in
func addFileID(fileName string, ID string) string {
	ext := path.Ext(fileName)
	base := fileName[:len(fileName)-len(ext)]
	return addID(base, ID) + ext
}

var idRe = regexp.MustCompile(`\{([A-Za-z0-9_-]{55,})\}`)

// findID finds an ID in string if one is there or ""
func findID(name string) string {
	match := idRe.FindStringSubmatch(name)
	if match == nil {
		return ""
	}
	return match[1]
}

// list the albums into an internal cache
// FIXME cache invalidation
func (f *Fs) listAlbums(shared bool) (all *albums, err error) {
	all, ok := f.albums[shared]
	if ok && all != nil {
		return all, nil
	}
	opts := rest.Opts{
		Method:     "GET",
		Path:       "/albums",
		Parameters: url.Values{},
	}
	if shared {
		opts.Path = "/sharedAlbums"
	}
	all = &albums{
		byID:    map[string]*api.Album{},
		byTitle: map[string]*api.Album{},
	}
	opts.Parameters.Set("pageSize", strconv.Itoa(albumChunks))
	lastID := ""
	for {
		var result api.ListAlbums
		var resp *http.Response
		err = f.pacer.Call(func() (bool, error) {
			resp, err = f.srv.CallJSON(&opts, nil, &result)
			return shouldRetry(resp, err)
		})
		if err != nil {
			return nil, errors.Wrap(err, "couldn't list albums")
		}
		newAlbums := result.Albums
		if shared {
			newAlbums = result.SharedAlbums
		}
		if len(newAlbums) > 0 && newAlbums[0].ID == lastID {
			// skip first if ID duplicated from last page
			newAlbums = newAlbums[1:]
		}
		if len(newAlbums) > 0 {
			lastID = newAlbums[len(newAlbums)-1].ID
		}
		all.albums = append(all.albums, newAlbums...)
		if result.NextPageToken == "" {
			break
		}
		opts.Parameters.Set("pageToken", result.NextPageToken)
	}
	// Dedupe the album names
	dupes := map[string]int{}
	for i := range all.albums {
		album := &all.albums[i]
		album.Title = strings.Replace(album.Title, "/", "／", -1)
		dupes[album.Title]++
	}
	for i := range all.albums {
		album := &all.albums[i]
		duplicated := dupes[album.Title] > 1
		if duplicated || album.Title == "" {
			album.Title = addID(album.Title, album.ID)
		}
	}
	// store the albums by ID and by name
	for i := range all.albums {
		album := &all.albums[i]
		all.byID[album.ID] = album
		all.byTitle[album.Title] = album
	}
	f.albums[shared] = all
	return all, nil
}

// listFn is called from list to handle an object.
type listFn func(remote string, object *api.MediaItem, isDirectory bool) error

// list the objects into the function supplied
//
// dir is the starting directory, "" for root
//
// Set recurse to read sub directories
func (f *Fs) list(dir string, filter api.SearchFilter, fn listFn) (err error) {
	opts := rest.Opts{
		Method: "POST",
		Path:   "/mediaItems:search",
	}
	filter.PageSize = listChunks
	filter.PageToken = ""
	lastID := ""
	for {
		var result api.MediaItems
		var resp *http.Response
		err = f.pacer.Call(func() (bool, error) {
			resp, err = f.srv.CallJSON(&opts, &filter, &result)
			return shouldRetry(resp, err)
		})
		if err != nil {
			return errors.Wrap(err, "couldn't list files")
		}
		items := result.MediaItems
		if len(items) > 0 && items[0].ID == lastID {
			// skip first if ID duplicated from last page
			items = items[1:]
		}
		if len(items) > 0 {
			lastID = items[len(items)-1].ID
		}
		for i := range items {
			item := &result.MediaItems[i]
			if i == 0 && item.ID == lastID {
				continue // skip first if ID duplicated from last page
			}
			remote := item.Filename
			remote = strings.Replace(remote, "/", "／", -1)
			err = fn(remote, item, false)
			if err != nil {
				return err
			}
		}
		if result.NextPageToken == "" {
			break
		}
		filter.PageToken = result.NextPageToken
	}

	return nil
}

// Convert a list item into a DirEntry
func (f *Fs) itemToDirEntry(remote string, item *api.MediaItem, isDirectory bool) (fs.DirEntry, error) {
	if isDirectory {
		d := fs.NewDir(remote, f.startTime)
		return d, nil
	}
	o, err := f.newObjectWithInfo(remote, item)
	if err != nil {
		return nil, err
	}
	return o, nil
}

// listDir lists a single directory
func (f *Fs) listDir(path string, dir string, filter api.SearchFilter) (entries fs.DirEntries, err error) {
	// List the objects
	err = f.list(dir, filter, func(remote string, item *api.MediaItem, isDirectory bool) error {
		entry, err := f.itemToDirEntry(path+remote, item, isDirectory)
		if err != nil {
			return err
		}
		if entry != nil {
			entries = append(entries, entry)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Dedupe the file names
	dupes := map[string]int{}
	for _, entry := range entries {
		o, ok := entry.(*Object)
		if ok {
			dupes[o.remote]++
		}
	}
	for _, entry := range entries {
		o, ok := entry.(*Object)
		if ok {
			duplicated := dupes[o.remote] > 1
			if duplicated || o.remote == "" {
				o.remote = addFileID(o.remote, o.id)
			}
		}
	}
	return entries, err
}

// dirPattern describes a single directory pattern
type dirPattern struct {
	re        string
	match     *regexp.Regexp
	canUpload bool
	isFile    bool
	toDirs    func(f *Fs, absPath string, match []string) (fs.DirEntries, error)
	toFilter  func(f *Fs, match []string) (api.SearchFilter, error)
}

// dirPatters is a slice of all the directory patterns
type dirPatterns []dirPattern

// mustCompile compiles the regexps in the dirPatterns
func (ds dirPatterns) mustCompile() dirPatterns {
	for i := range ds {
		pattern := &ds[i]
		pattern.match = regexp.MustCompile(pattern.re)
	}
	return ds
}

// match finds the path passed in in the matching structure and
// returns the parameters and a pointer to the match, or nil.
func (ds dirPatterns) match(root string, itemPath string) (match []string, prefix string, pattern *dirPattern) {
	itemPath = strings.Trim(itemPath, "/")
	absPath := path.Join(root, itemPath)
	prefix = strings.Trim(absPath[len(root):], "/")
	if prefix != "" {
		prefix += "/"
	}
	for i := range ds {
		pattern = &ds[i]
		match = pattern.match.FindStringSubmatch(absPath)
		if match != nil {
			return
		}
	}
	return nil, "", nil
}

// Return the years from 2000 to today
// FIXME make configurable?
func years(f *Fs, absPath string, match []string) (entries fs.DirEntries, err error) {
	currentYear := time.Now().Year()
	for year := 2000; year <= currentYear; year++ {
		entries = append(entries, fs.NewDir(absPath+fmt.Sprint(year), f.startTime))
	}
	return entries, nil
}

// Return the months in a given year
func months(f *Fs, absPath string, match []string) (entries fs.DirEntries, err error) {
	year := match[1]
	for month := 1; month <= 12; month++ {
		entries = append(entries, fs.NewDir(fmt.Sprintf("%s%s-%02d", absPath, year, month), f.startTime))
	}
	return entries, nil
}

// Return the days in a given year
func days(f *Fs, absPath string, match []string) (entries fs.DirEntries, err error) {
	year := match[1]
	current, err := time.Parse("2006", year)
	if err != nil {
		return nil, errors.Errorf("bad year %q", match[1])
	}
	currentYear := current.Year()
	for current.Year() == currentYear {
		entries = append(entries, fs.NewDir(absPath+current.Format("2006-01-02"), f.startTime))
		current = current.AddDate(0, 0, 1)
	}
	return entries, nil
}

// This filters on year/month/day as provided
func yearMonthDayFilter(f *Fs, match []string) (sf api.SearchFilter, err error) {
	year, err := strconv.Atoi(match[1])
	if err != nil || year < 1000 || year > 3000 {
		return sf, errors.Errorf("bad year %q", match[1])
	}
	sf = api.SearchFilter{
		Filters: &api.Filters{
			DateFilter: &api.DateFilter{
				Dates: []api.Date{
					{
						Year: year,
					},
				},
			},
		},
	}
	if len(match) >= 3 {
		month, err := strconv.Atoi(match[2])
		if err != nil || month < 1 || month > 12 {
			return sf, errors.Errorf("bad month %q", match[2])
		}
		sf.Filters.DateFilter.Dates[0].Month = month
	}
	if len(match) >= 4 {
		day, err := strconv.Atoi(match[3])
		if err != nil || day < 1 || day > 31 {
			return sf, errors.Errorf("bad day %q", match[3])
		}
		sf.Filters.DateFilter.Dates[0].Day = day
	}
	return sf, nil
}

// Turns the albums into directories
func albumsToDirs(f *Fs, shared bool, absPath string, match []string) (entries fs.DirEntries, err error) {
	albums, err := f.listAlbums(shared)
	if err != nil {
		return nil, err
	}
	for i := range albums.albums {
		album := &albums.albums[i]
		entries = append(entries, fs.NewDir(absPath+album.Title, f.startTime).SetID(album.ID))
	}
	return entries, nil
}

// Turns albums into search filter
func albumsToFilter(f *Fs, shared bool, match []string) (sf api.SearchFilter, err error) {
	albumName := match[1]
	id := findID(albumName)
	if id == "" {
		albums, err := f.listAlbums(shared)
		if err != nil {
			return sf, err
		}
		album, ok := albums.byTitle[albumName]
		if !ok {
			return sf, fs.ErrorDirNotFound
		}
		id = album.ID
	}
	return api.SearchFilter{AlbumID: id}, nil
}

// No trailing /
var patterns = dirPatterns{
	{
		re: `^$`,
		toDirs: func(f *Fs, absPath string, match []string) (fs.DirEntries, error) {
			return fs.DirEntries{
				fs.NewDir(absPath+"media", f.startTime),
				fs.NewDir(absPath+"album", f.startTime),
				fs.NewDir(absPath+"shared-album", f.startTime),
				fs.NewDir(absPath+"upload", f.startTime),
			}, nil
		},
	},
	{
		re: `^upload$`,
		toDirs: func(f *Fs, absPath string, match []string) (fs.DirEntries, error) {
			return fs.DirEntries{}, nil
		},
	},
	{
		re:        `^upload/([^/]+)$`,
		canUpload: true,
		isFile:    true,
	},
	{
		re: `^media$`,
		toDirs: func(f *Fs, absPath string, match []string) (fs.DirEntries, error) {
			return fs.DirEntries{
				fs.NewDir(absPath+"all", f.startTime),
				fs.NewDir(absPath+"by-year", f.startTime),
				fs.NewDir(absPath+"by-month", f.startTime),
				fs.NewDir(absPath+"by-day", f.startTime),
			}, nil
		},
	},
	{
		re: `^media/all$`,
		toFilter: func(f *Fs, match []string) (sf api.SearchFilter, err error) {
			return sf, nil
		},
	},
	{
		re:     `^media/all/([^/]+)$`,
		isFile: true,
	},
	{
		re:     `^media/by-year$`,
		toDirs: years,
	},
	{
		re:       `^media/by-year/(\d{4})$`,
		toFilter: yearMonthDayFilter,
	},
	{
		re:     `^media/by-year/(\d{4})/([^/]+)$`,
		isFile: true,
	},
	{
		re:     `^media/by-month$`,
		toDirs: years,
	},
	{
		re:     `^media/by-month/(\d{4})$`,
		toDirs: months,
	},
	{
		re:       `^media/by-month/\d{4}/(\d{4})-(\d{2})$`,
		toFilter: yearMonthDayFilter,
	},
	{
		re:     `^media/by-month/\d{4}/(\d{4})-(\d{2})/([^/]+)$`,
		isFile: true,
	},
	{
		re:     `^media/by-day$`,
		toDirs: years,
	},
	{
		re:     `^media/by-day/(\d{4})$`,
		toDirs: days,
	},
	{
		re:       `^media/by-day/\d{4}/(\d{4})-(\d{2})-(\d{2})$`,
		toFilter: yearMonthDayFilter,
	},
	{
		re:     `^media/by-day/\d{4}/(\d{4})-(\d{2})-(\d{2})/([^/]+)$`,
		isFile: true,
	},
	{
		re: `^album$`,
		toDirs: func(f *Fs, absPath string, match []string) (entries fs.DirEntries, err error) {
			return albumsToDirs(f, false, absPath, match)
		},
	},
	{
		re: `^album/([^/]+)$`,
		toFilter: func(f *Fs, match []string) (sf api.SearchFilter, err error) {
			return albumsToFilter(f, false, match)

		},
	},
	{
		re:        `^album/([^/]+)/([^/]+)$`,
		canUpload: true,
		isFile:    true,
	},
	{
		re: `^shared-album$`,
		toDirs: func(f *Fs, absPath string, match []string) (entries fs.DirEntries, err error) {
			return albumsToDirs(f, true, absPath, match)
		},
	},
	{
		re: `^shared-album/([^/]+)$`,
		toFilter: func(f *Fs, match []string) (sf api.SearchFilter, err error) {
			return albumsToFilter(f, true, match)

		},
	},
	{
		re:        `^shared-album/([^/]+)/([^/]+)$`,
		canUpload: true,
		isFile:    true,
	},
}.mustCompile()

// List the objects and directories in dir into entries.  The
// entries can be returned in any order but should be for a
// complete directory.
//
// dir should be "" to list the root, and should not have
// trailing slashes.
//
// This should return ErrDirNotFound if the directory isn't
// found.
func (f *Fs) List(dir string) (entries fs.DirEntries, err error) {
	match, prefix, pattern := patterns.match(f.root, dir)
	if pattern == nil || pattern.isFile {
		return nil, fs.ErrorDirNotFound
	}
	if pattern.toDirs != nil {
		return pattern.toDirs(f, prefix, match)
	}
	if pattern.toFilter != nil {
		filter, err := pattern.toFilter(f, match)
		if err != nil {
			return nil, errors.Wrapf(err, "bad filter when listing %q", dir)
		}
		return f.listDir(prefix, dir, filter)
	}
	return nil, fs.ErrorDirNotFound
}

// Put the object into the bucket
//
// Copy the reader in to the new object which is returned
//
// The new object may have been created if an error is returned
func (f *Fs) Put(in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	// Temporary Object under construction
	o := &Object{
		fs:     f,
		remote: src.Remote(),
	}
	return o, o.Update(in, src, options...)
}

// Mkdir creates the bucket if it doesn't exist
func (f *Fs) Mkdir(dir string) (err error) {
	return errFIXME
}

// Rmdir deletes the bucket if the fs is at the root
//
// Returns an error if it isn't empty
func (f *Fs) Rmdir(dir string) (err error) {
	return errFIXME
}

// Precision returns the precision
func (f *Fs) Precision() time.Duration {
	return time.Second
}

// Hashes returns the supported hash sets.
func (f *Fs) Hashes() hash.Set {
	return hash.Set(hash.None)
}

// ------------------------------------------------------------

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// Return a string version
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// Hash returns the Md5sum of an object returning a lowercase hex string
func (o *Object) Hash(t hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

// Size returns the size of an object in bytes
func (o *Object) Size() int64 {
	if !o.fs.opt.ReadSize || o.bytes >= 0 {
		return o.bytes
	}
	var resp *http.Response
	opts := rest.Opts{
		Method:  "HEAD",
		RootURL: o.url + "=d",
	}
	var err error
	err = o.fs.pacer.Call(func() (bool, error) {
		resp, err = o.fs.srv.Call(&opts)
		return shouldRetry(resp, err)
	})
	if err != nil {
		fs.Debugf(o, "Reading size failed: %v", err)
	} else {
		lengthStr := resp.Header.Get("Content-Length")
		length, err := strconv.ParseInt(lengthStr, 10, 64)
		if err != nil {
			fs.Debugf(o, "Reading size failed to parse Content_length %q: %v", lengthStr, err)
		} else {
			o.bytes = length
		}
	}
	return o.bytes
}

// setMetaData sets the fs data from a storage.Object
func (o *Object) setMetaData(info *api.MediaItem) {
	o.url = info.BaseURL
	o.id = info.ID
	o.bytes = -1 // FIXME
	o.mimeType = info.MimeType
	o.modTime = info.MediaMetadata.CreationTime
}

// readMetaData gets the metadata if it hasn't already been fetched
//
// it also sets the info
func (o *Object) readMetaData() (err error) {
	if !o.modTime.IsZero() {
		return nil
	}
	dir, fileName := path.Split(o.remote)
	dir = strings.Trim(dir, "/")
	_, _, pattern := patterns.match(o.fs.root, o.remote)
	if pattern == nil {
		return fs.ErrorObjectNotFound
	}
	if !pattern.isFile {
		return fs.ErrorNotAFile
	}
	// If have ID fetch it directly
	if id := findID(fileName); id != "" {
		opts := rest.Opts{
			Method: "GET",
			Path:   "/mediaItems/" + id,
		}
		var item api.MediaItem
		var resp *http.Response
		err = o.fs.pacer.Call(func() (bool, error) {
			resp, err = o.fs.srv.CallJSON(&opts, nil, &item)
			return shouldRetry(resp, err)
		})
		if err != nil {
			return errors.Wrap(err, "couldn't get media item")
		}
		o.setMetaData(&item)
		return nil
	}
	// Otherwise list the directory the file is in
	entries, err := o.fs.List(dir)
	if err != nil {
		return err
	}
	// and find the file in the directory
	for _, entry := range entries {
		if entry.Remote() == o.remote {
			if newO, ok := entry.(*Object); ok {
				*o = *newO
				return nil
			}
		}
	}
	return fs.ErrorObjectNotFound
}

// ModTime returns the modification time of the object
//
// It attempts to read the objects mtime and if that isn't present the
// LastModified returned in the http headers
func (o *Object) ModTime() time.Time {
	err := o.readMetaData()
	if err != nil {
		// fs.Logf(o, "Failed to read metadata: %v", err)
		return time.Now()
	}
	return o.modTime
}

// SetModTime sets the modification time of the local fs object
func (o *Object) SetModTime(modTime time.Time) (err error) {
	return fs.ErrorCantSetModTime
}

// Storable returns a boolean as to whether this object is storable
func (o *Object) Storable() bool {
	return true
}

// Open an object for read
func (o *Object) Open(options ...fs.OpenOption) (in io.ReadCloser, err error) {
	var resp *http.Response
	opts := rest.Opts{
		Method:  "GET",
		RootURL: o.url + "=d",
		Options: options,
	}
	err = o.fs.pacer.Call(func() (bool, error) {
		resp, err = o.fs.srv.Call(&opts)
		return shouldRetry(resp, err)
	})
	if err != nil {
		return nil, err
	}
	return resp.Body, err
}

// Update the object with the contents of the io.Reader, modTime and size
//
// The new object may have been created if an error is returned
func (o *Object) Update(in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	_, _, pattern := patterns.match(o.fs.root, o.remote)
	if pattern == nil || !pattern.isFile || !pattern.canUpload {
		return errCantUpload
	}
	// FIXME implement upload
	return errFIXME
}

// Remove an object
func (o *Object) Remove() (err error) {
	return errFIXME
}

// MimeType of an Object if known, "" otherwise
func (o *Object) MimeType() string {
	return o.mimeType
}

// ID of an Object if known, "" otherwise
func (o *Object) ID() string {
	return o.id
}

// Check the interfaces are satisfied
var (
	_ fs.Fs        = &Fs{}
	_ fs.Object    = &Object{}
	_ fs.MimeTyper = &Object{}
	_ fs.IDer      = &Object{}
)
