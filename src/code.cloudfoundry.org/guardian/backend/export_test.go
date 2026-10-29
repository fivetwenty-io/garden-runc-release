package backend

// KnownKinds returns every kind that guardian recognises, so that specs can
// enumerate them without a second hand-kept list.
func KnownKinds() []Kind {
	kinds := make([]Kind, 0, len(known))
	for k := range known {
		kinds = append(kinds, k)
	}
	return kinds
}
