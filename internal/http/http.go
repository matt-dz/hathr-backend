package http

import (
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

type Client struct {
	*retryablehttp.Client
}

func New() *Client {
	client := retryablehttp.NewClient()
	client.RetryMax = 3
	client.RetryWaitMax = time.Second * 10
	return &Client{
		Client: client,
	}
}
