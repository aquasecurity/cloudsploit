var sender = require( './email/sender.js' )
var senderSummary = require( './email/senderSummary.js' )
var suppression = require( './email/suppression.js' )
var suppressionSummary = require( './email/suppressionSummary.js' )

module.exports = {
    sender: sender,
    senderSummary: senderSummary,
    suppression: suppression,
    suppressionSummary: suppressionSummary
}