package api

import (
	"fmt"
	"time"
)

// ErrorDetails in the internals of the Error type
type ErrorDetails struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

// Error is returned on errors
type Error struct {
	Details ErrorDetails `json:"error"`
}

// Error statisfies error interface
func (e *Error) Error() string {
	return fmt.Sprintf("%s (%d %s)", e.Details.Message, e.Details.Code, e.Details.Status)
}

// Album of photos
type Album struct {
	ID                    string `json:"id"`
	Title                 string `json:"title"`
	ProductURL            string `json:"productUrl"`
	MediaItemsCount       string `json:"mediaItemsCount"`
	CoverPhotoBaseURL     string `json:"coverPhotoBaseUrl"`
	CoverPhotoMediaItemID string `json:"coverPhotoMediaItemId"`
}

// ListAlbums is returned from albums.list and sharedAlbums.list
type ListAlbums struct {
	Albums        []Album `json:"albums"`
	SharedAlbums  []Album `json:"sharedAlbums"`
	NextPageToken string  `json:"nextPageToken"`
}

// MediaItem is a photo or video
type MediaItem struct {
	ID            string `json:"id"`
	ProductURL    string `json:"productUrl"`
	BaseURL       string `json:"baseUrl"`
	MimeType      string `json:"mimeType"`
	MediaMetadata struct {
		CreationTime time.Time `json:"creationTime"`
		Width        string    `json:"width"`
		Height       string    `json:"height"`
		Photo        struct {
		} `json:"photo"`
	} `json:"mediaMetadata"`
	Filename string `json:"filename"`
}

// MediaItems is returned from mediaitems.list, mediaitems.search
type MediaItems struct {
	MediaItems    []MediaItem `json:"mediaItems"`
	NextPageToken string      `json:"nextPageToken"`
}

//Content categories
// NONE	Default content category. This category is ignored when any other category is used in the filter.
// LANDSCAPES	Media items containing landscapes.
// RECEIPTS	Media items containing receipts.
// CITYSCAPES	Media items containing cityscapes.
// LANDMARKS	Media items containing landmarks.
// SELFIES	Media items that are selfies.
// PEOPLE	Media items containing people.
// PETS	Media items containing pets.
// WEDDINGS	Media items from weddings.
// BIRTHDAYS	Media items from birthdays.
// DOCUMENTS	Media items containing documents.
// TRAVEL	Media items taken during travel.
// ANIMALS	Media items containing animals.
// FOOD	Media items containing food.
// SPORT	Media items from sporting events.
// NIGHT	Media items taken at night.
// PERFORMANCES	Media items from performances.
// WHITEBOARDS	Media items containing whiteboards.
// SCREENSHOTS	Media items that are screenshots.
// UTILITY	Media items that are considered to be utility. These include, but aren't limited to documents, screenshots, whiteboards etc.
// ARTS	Media items containing art.
// CRAFTS	Media items containing crafts.
// FASHION	Media items related to fashion.
// HOUSES	Media items containing houses.
// GARDENS	Media items containing gardens.
// FLOWERS	Media items containing flowers.
// HOLIDAYS	Media items taken of holidays.

// MediaTypes
// ALL_MEDIA	Treated as if no filters are applied. All media types are included.
// VIDEO	All media items that are considered videos. This also includes movies the user has created using the Google Photos app.
// PHOTO	All media items that are considered photos. This includes .bmp, .gif, .ico, .jpg (and other spellings), .tiff, .webp and special photo types such as iOS live photos, Android motion photos, panoramas, photospheres.

// Features
// NONE	Treated as if no filters are applied. All features are included.
// FAVORITES	Media items that the user has marked as favorites in the Google Photos app.

// Date is used as part of SearchFilter
type Date struct {
	Year  int `json:"year,omitempty"`
	Month int `json:"month,omitempty"`
	Day   int `json:"day,omitempty"`
}

// DateFilter is uses to add date ranges to media item queries
type DateFilter struct {
	Dates  []Date `json:"dates,omitempty"`
	Ranges []struct {
		StartDate Date `json:"startDate,omitempty"`
		EndDate   Date `json:"endDate,omitempty"`
	} `json:"ranges,omitempty"`
}

// ContentFilter is uses to add content categories to media item queries
type ContentFilter struct {
	IncludedContentCategories []string `json:"includedContentCategories,omitempty"`
	ExcludedContentCategories []string `json:"excludedContentCategories,omitempty"`
}

// MediaTypeFilter is uses to add media types to media item queries
type MediaTypeFilter struct {
	MediaTypes []string `json:"mediaTypes,omitempty"`
}

// FeatureFilter is uses to add features to media item queries
type FeatureFilter struct {
	IncludedFeatures []string `json:"includedFeatures,omitempty"`
}

// Filters combines all the filter types for media item queries
type Filters struct {
	DateFilter               *DateFilter      `json:"dateFilter,omitempty"`
	ContentFilter            *ContentFilter   `json:"contentFilter,omitempty"`
	MediaTypeFilter          *MediaTypeFilter `json:"mediaTypeFilter,omitempty"`
	FeatureFilter            *FeatureFilter   `json:"featureFilter,omitempty"`
	IncludeArchivedMedia     *bool            `json:"includeArchivedMedia,omitempty"`
	ExcludeNonAppCreatedData *bool            `json:"excludeNonAppCreatedData,omitempty"`
}

// SearchFilter is uses with mediaItems.search
type SearchFilter struct {
	AlbumID   string   `json:"albumId,omitempty"`
	PageSize  int      `json:"pageSize"`
	PageToken string   `json:"pageToken,omitempty"`
	Filters   *Filters `json:"filters,omitempty"`
}
