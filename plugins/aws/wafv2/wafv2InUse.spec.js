const expect = require('chai').expect;
var wafv2InUse = require('./wafv2InUse');

const webACLs = [
    {
        Name: "WebACLexample",
        WebACLId: "webacl-1472061481310"
    },
    {
        Name: "WebACLexample2",
        WebACLId: "webacl-1472061481390"
    }
]

const createCache = (webACLs) => {
    return {
        wafv2: {
            listWebACLs: {
                'us-east-2': {
                    data: webACLs
                },
                'us-east-1': {
                    data: webACLs
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        wafv2: {
            listWebACLs: {
                'us-east-1': {
                    err: {
                        message: 'Error listing transfer servers'
                    }
                }
            }
        }
    };
};


describe('wafv2InUse', function () {
    describe('run', function () {
        it('should PASS if WAF is being used', function (done) {
            const cache = createCache(webACLs);
            wafv2InUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('WAFV2 is enabled');
                done();
            });
        });

        it('should FAIL if no application is using WAF', function (done) {
            const cache = createCache([]);
            wafv2InUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('WAFV2 is not enabled');
                done();
            });
        });

        it('should unknown if unable to listWebACLs', function (done) {
            const cache = createErrorCache();
            wafv2InUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
