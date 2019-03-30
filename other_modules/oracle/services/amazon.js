var bucket = require( './amazon/bucket.js' );
var locationConstraint = require( './amazon/locationConstraint.js' );
var obj = require( './amazon/obj.js' );
var service = require( './amazon/service.js' );
var tagging = require( './amazon/tagging.js' );


module.exports = {
      bucket: bucket,
      locationConstraint: locationConstraint,
      obj: obj,
      service: service,
      tagging: tagging
}