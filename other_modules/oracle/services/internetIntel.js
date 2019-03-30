var geolocation = require( './internetIntel/geolocation.js' )
var marketLatency = require( './internetIntel/marketLatency.js' )
var tracerouteResult = require( './internetIntel/tracerouteResult.js' )
var vantagePointSummary = require( './internetIntel/vantagePointSummary.js' )

module.exports = {
    geolocation: geolocation,
    marketLatency: marketLatency,
    tracerouteResult: tracerouteResult,
    vantagePointSummary: vantagePointSummary
}