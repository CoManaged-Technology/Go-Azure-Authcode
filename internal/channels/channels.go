package channels

import "github.com/openmspsolutions/go-azure-authcode/internal/azrequests"

var AuthEvents chan *azrequests.Token

func InitChannels() {
	AuthEvents = make(chan *azrequests.Token)
}
