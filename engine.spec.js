var engine = require('./engine');


describe('engine', function () {
    it('should run with no arguments', function () {
        // Although we don't pass in anything, this is enough to test
        // that our dependencies are actually installed.
        engine({}, {cloud: 'aws'});
    })
});
