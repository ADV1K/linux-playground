package handlers

import (
	"github.com/adv1k/linux-playground/store"
)

type Handler struct {
	store *store.Storage
}

func New(store *store.Storage) *Handler {
	return &Handler{
		store: store,
	}
}
