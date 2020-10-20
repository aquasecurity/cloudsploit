var engine = require('./engine');


describe('engine', function () {
    it('should run with no arguments', function () {
        // Although we don't pass in anything, this is enough to test
        // that our dependencies are actually installed.
        // We set plugin to something that doesn't exist to prevent any actual api calls from being made
        engine({}, {cloud: 'aws', plugin: 'does not exist'});
    })
});
