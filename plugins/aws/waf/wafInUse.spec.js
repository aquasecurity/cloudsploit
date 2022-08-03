const expect = require('chai').expect;
var wafInUse = require('./wafInUse');

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

const createGlobalCache = (webACLs) => {
    return {
        waf: {
            listWebACLs: {
                'us-east-1': {
                    data: webACLs
                }
            }
        }
    };
};

const createRegionalCache = (webACLs) => {
    return {
        wafregional: {
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
        waf: {
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


describe('wafInUse', function () {
    describe('run', function () {
        it('should PASS if WAF is being used globally', function (done) {
            const cache = createGlobalCache(webACLs);
            wafInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('WAF is enabled');
                done();
            });
        });

        it('should PASS if WAF is being used regionally', function (done) {
            const cache = createRegionalCache(webACLs);
            wafInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('WAF is enabled');
                expect(results[0].region).to.include('us-east-1');
                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('WAF is enabled');
                expect(results[1].region).to.include('us-east-2');
                done();
            });
        });

        it('should FAIL if no application is using WAF globally', function (done) {
            const cache = createGlobalCache([]);
            wafInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('WAF is not enabled');
                done();
            });
        });

        it('should FAIL if no application is using WAF regionally', function (done) {
            const cache = createRegionalCache([]);
            wafInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('WAF is not enabled');
                expect(results[0].region).to.include('us-east-1');
                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('WAF is not enabled');
                expect(results[1].region).to.include('us-east-2');
                done();
            });
        });

        it('should unknown if unable to listWebACLs', function (done) {
            const cache = createErrorCache();
            wafInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
