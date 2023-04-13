const expect = require('chai').expect;
var osCrossAccountAccess = require('./opensearchCrossAccountAccess');

const domainNames = [
  {
      "DomainName": "test-domain-1"
  },
];

const domains = [
    {
        'DomainStatus': {
            'DomainId': '111111111111/test-domain-1',
            'DomainName': 'test-domain-1',
            'ARN': 'arn:aws:es:us-east-1:11111111111:domain/test-domain-1',
            'Created': true,
            'Deleted': false,
            'AccessPolicies': '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::211111111111:user/y"},"Action":"es:*","Resource":"arn:aws:events:us-east-1:111111111111:domain/test-domain-1/*"}]}',
        }
    },
    {
        'DomainStatus': {
            'DomainId': '111111111111/test-domain-1',
            'DomainName': 'test-domain-1',
            'ARN': 'arn:aws:es:us-east-1:111111111111:domain/test-domain-1',
            'Created': true,
            'Deleted': false,
            'AccessPolicies': '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/x"},"Action":"es:*","Resource":"arn:aws:events:us-east-1:111111111111:domain/test-domain-1/*"}]}',
        }
    },
    {
        'DomainStatus': {
            'DomainId': '111111111111/test-domain-1',
            'DomainName': 'test-domain-1',
            'ARN': 'arn:aws:es:us-east-1:111111111111:domain/test-domain-1',
            'Created': true,
            'Deleted': false,
            'AccessPolicies': '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"es:*","Resource":"arn:aws:es:us-east-1:111111111111:domain/test-domain-1/*"}]}',
        }
    },
    {
        'DomainStatus': {
            'DomainId': '111111111111/test-domain-1',
            'DomainName': 'test-domain-1',
            'ARN': 'arn:aws:es:us-east-1:111111111111:domain/test-domain-1',
            'Created': true,
            'Deleted': false,
        }
    },
];

const organizationAccounts = [
    {
        "Id": "211111111111",
        "Arn": "arn:aws:organizations::211111111111:account/o-sb9qmv2zif/111111111111",
        "Email": "xyz@gmail.com",
        "Name": "test-role",
        "Status": "ACTIVE",
        "JoinedMethod": "INVITED",
        "JoinedTimestamp": "2020-12-27T10:47:14.057Z"
    },
    {
        "Id": "123456654322",
        "Arn": "arn:aws:organizations::123456654322:account/o-sb9qmv2zif/123456654322",
        "Email": "xyz@gmail.com",
        "Name": "test-role",
        "Status": "ACTIVE",
        "JoinedMethod": "INVITED",
        "JoinedTimestamp": "2020-12-27T10:47:14.057Z"
    }
]

const createCache = (domainNames, domains, accounts, domainNamesErr,domainsErr) => {
    return {
        opensearch: {
            listDomainNames: {
                'us-east-1': {
                    data: domainNames,
                    err: domainNamesErr
                }
            },
            describeDomain: {
                'us-east-1': {
                    'test-domain-1': {
                        data: domains,
                        err: domainsErr
                    }
                }
            }
        },
        sts: {
            getCallerIdentity: {
                'us-east-1':{
                    data: '111111111111'
                }
            }
        },
        organizations: {
            listAccounts: {
                'us-east-1': {
                    data: accounts
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        opensearch: {
            listDomainNames: {
                'us-east-1': null
            },
            describeDomain: {
                'us-east-1': null
            }
        }
    };
};

describe('osCrossAccountAccess', function () {
    describe('run', function () {

        it('should PASS if opensearch domain has cross-account access policy attached', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            osCrossAccountAccess.run(cache, {"os_whitelisted_aws_account_principals":['arn:aws:iam::211111111111:user/y']}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.includes('OpenSearch domain contains trusted account principals only')
                done();
            });
        });

        it('should PASS if cross-account role contains organization account ID and setting to allow organization account is true', function (done) {
            const cache = createCache([domainNames[0]], domains[0], [organizationAccounts[0]]);
            osCrossAccountAccess.run(cache, { "os_whitelist_aws_organization_accounts": "true" }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.includes('OpenSearch domain contains trusted account principals only')
                done();
            });
        });

        it('should PASS if opensearch domain does not have cross-account access policy attached', function (done) {
            const cache = createCache([domainNames[0]], domains[1]);
            osCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.includes('OpenSearch domain does not contain cross-account policy statement')
                done();
            });
        });
        
        it('should PASS if no opensearch Domain policy found', function (done) {
            const cache = createCache([domainNames[0]], domains[3]);
            osCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.includes('OpenSearch domain does not have access policy defined')
                done();
            });
        });

        it('should FAIL if no opensearch domain found', function (done) {
            const cache = createCache([]);
            osCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.includes('No OpenSearch domains found')
                done();
            });
        });

        it('should UNKNOWN if unable to describe opensearch domain', function (done) {
            const cache = createCache([], [], [], { message: 'Unable to query ES domains' });
            osCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.includes('Unable to query for OpenSearch domains')
                done();
            });
        });

        it('should not return anything if query opensearch domains response not found', function (done) {
            const cache = createNullCache();
            osCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});