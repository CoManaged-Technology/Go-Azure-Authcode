package controllers

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openmspsolutions/go-azure-authcode/internal/azrequests"
	"github.com/openmspsolutions/go-azure-authcode/internal/channels"
	"github.com/openmspsolutions/go-azure-authcode/internal/helpers"
)

type AuthCode struct {
	Code    string `form:"code"`
	IdToken string `form:"id_token"`
	State   string `form:"state"`
}

func GetRefreshToken(context *gin.Context) {
	var request AuthCode
	if err := context.Bind(&request); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		context.Abort()
		log.Println(err)
		return
	}

	token, err := azrequests.AzRequestsClient.GetToken(request.Code)
	if err != nil {
		log.Println(err)
	}

	helpers.SendResponse(context, helpers.Response{
		Status:  http.StatusOK,
		Message: []string{"OK"},
	})

	channels.AuthEvents <- &token
}
