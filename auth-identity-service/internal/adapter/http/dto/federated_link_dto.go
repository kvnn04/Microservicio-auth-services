package dto

// LinkInitiateRequest initiate (Step-Up + password si aplica).
type LinkInitiateRequest struct {
	CurrentPassword string `json:"current_password,omitempty"`
}

// LinkInitiateResponse 200 con URL (SPA abre popup, no 302).
type LinkInitiateResponse struct {
	Success bool `json:"success"`
	Data    struct {
		URL       string `json:"url"`
		State     string `json:"state"`
		ExpiresIn int    `json:"expires_in"`
	} `json:"data"`
}

// LinkStatusResponse 200 linked/already_linked/unlinked.
type LinkStatusResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Status   string `json:"status"`
		Provider string `json:"provider"`
	} `json:"data"`
}

// LinkedListResponse 200 lista enmascarada.
type LinkedListResponse struct {
	Success bool `json:"success"`
	Data    struct {
		Linked []LinkedListItem `json:"linked"`
	} `json:"data"`
}

// LinkedListItem espejo del servicio (sin sub plano).
type LinkedListItem struct {
	Provider    string `json:"provider"`
	EmailMasked string `json:"email_masked"`
	SubHash     string `json:"sub_hash"`
	LinkedAt    string `json:"linked_at"`
}

// UnlinkRequest body unlink (DELETE con body o POST /unlink).
type UnlinkRequest struct {
	CurrentPassword string `json:"current_password,omitempty"`
}
