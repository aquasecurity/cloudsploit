const expect = require('chai').expect;
var aclRulesDefaultAction = require('./aclRulesDefaultAction');

const webACLs = [
    {
        Name: "WebACLexample",
        Id: "234",
        ARN: "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/test-poc/234"
    },
]
const getWebAcl = [
    {
        WebACL: {
            "ARN": "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/test-poc/234",
            "DefaultAction": {
                "Block": {},
            },

        }
    },
    {
        WebACL:{
            "ARN": "arn:aws:wafv2:us-east-1:111122223333:regional/webacl/test-poc/234",
            "DefaultAction": {
                "Allow": {},
            },

        }
    }
]

const createCache = (webACLs, getWebAcl) => {
    var arn = (webACLs && webACLs.length) ? webACLs[0].ARN : null;
    return {
        wafv2: {
            listWebACLs: {
                'us-east-1': {
                    data: webACLs
                }
            },
            getWebACL: {
                'us-east-1': {
                    [arn]: {
                        data: getWebAcl
                    }
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


describe('aclRulesDefaultAction', function () {
    describe('run', function () {
        it('should PASS if Default action for web ACL rule is to Block', function (done) {
            const cache = createCache([webACLs[0]], getWebAcl[0]);
            aclRulesDefaultAction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Default action for web ACL rule is set to Block');
                done();
            });
        });

        it('should FAIL if Default action for web ACL rule is not Block', function (done) {
            const cache = createCache([webACLs[0]], getWebAcl[1]);
            aclRulesDefaultAction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Default action for web ACL rule is not set to Block');
                done();
            });
        });

        it('should unknown if unable to listWebACLs', function (done) {
            const cache = createErrorCache();
            aclRulesDefaultAction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list WAFV2 web ACLs:')
                done();
            });
        });
        it('should unknown if unable to get web acl details', function (done) {
            const cache = createCache([webACLs[0]], null)
            aclRulesDefaultAction.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to get web ACL details:')
                done();
            });
        });
    });
});