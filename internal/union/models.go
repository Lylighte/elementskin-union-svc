package union

// Profile represents a Union profile entry as returned by the Hub.
type Profile struct {
	UUID       string `json:"uuid,omitempty"`
	Name       string `json:"name,omitempty"`
	InternalID string `json:"internal_id,omitempty"`
}

// BlacklistEntry represents a Union blacklist record.
type BlacklistEntry struct {
	ID         string `json:"id,omitempty"`
	Email      string `json:"email,omitempty"`
	Source     string `json:"source,omitempty"`
	Reason     string `json:"reason,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
	ValidUntil string `json:"valid_until,omitempty"`
}
