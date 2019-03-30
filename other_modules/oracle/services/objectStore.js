var bucket = require( './objectStore/bucket.js' );
var namespace = require( './objectStore/namespace.js' );
var obj = require( './objectStore/obj.js' );
var preauthenticatedRequest = require( './objectStore/preauthenticatedRequest.js');
var objectlifecyclePolicy = require( './objectStore/objectLifecyclePolicy.js');
var workRequest = require( './objectStore/workRequest.js');
var workRequestError = require( './objectStore/workRequestError.js');
var workRequestLogEntry = require( './objectStore/workRequestLogEntry.js');


module.exports = {
    bucket: bucket,
    namespace: namespace,
    obj: obj,
    preauthenticatedRequest : preauthenticatedRequest,
    objectlifecyclePolicy: objectlifecyclePolicy,
    workRequest: workRequest,
    workRequestError: workRequestError,
    workRequestLogEntry: workRequestLogEntry
}