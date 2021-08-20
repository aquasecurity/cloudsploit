const expect = require('chai').expect;
const esDesiredInstanceTypes = require('./esDesiredInstanceTypes');

const domainNames = [
    {
        "DomainName": "test-domain"
    },
];

const domains = [
    {
        "DomainStatus": {
            "DomainId": "1123456654321/test-domain",
            "DomainName": "test-domain",
            "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain",
            "ElasticsearchClusterConfig": {
                "InstanceType": "t2.small.elasticsearch",
                "DedicatedMasterType": "t2.small.elasticsearch",
            }           
        }
    },
    {
        "DomainStatus": {
            "DomainId": "1123456654321/test-domain",
            "DomainName": "test-domain",
            "ARN": "arn:aws:es:us-east-1:1123456654321:domain/test-domain",
            "ElasticsearchClusterConfig": {
                "InstanceType": "t2.small.elasticsearch",
            }           
        }
    },
];

const createCache = (domainNames, domains) => {
    if (domainNames && domainNames.length) var name = domainNames[0].DomainName;
    return {
        es: {
            listDomainNames: {
                'us-east-1': {
                    data: domainNames,
                },
            },
            describeElasticsearchDomain: {
                'us-east-1': {
                    [name]: {
                        data: domains
                    }
                }
            }
        },
    };
};

const createErrorCache = () => {
    return {
        es: {
            listDomainNames: {
                'us-east-1': {
                    err: {
                        message: 'error listing domain names'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        es: {
            listDomainNames: {
                'us-east-1': null,
            },
        },
    };
};

describe('esDesiredInstanceTypes', function () {
    describe('run', function () {
        it('should FAIL if dedicated master and data node are not of desired instance type', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            esDesiredInstanceTypes.run(cache, {es_desired_data_instance_type: 't2.medium.elasticsearch', es_desired_master_instance_type: 't2.medium.elasticsearch'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if dedicated master instance is not of desired type', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            esDesiredInstanceTypes.run(cache, {es_desired_master_instance_type: 't2.medium.elasticsearch'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if data node instance is not of desired type', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            esDesiredInstanceTypes.run(cache, {es_desired_data_instance_type: 't2.medium.elasticsearch'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        
        it('should PASS if master and data instances re of desired instance types', function (done) {
            const cache = createCache([domainNames[0]], domains[1]);
            esDesiredInstanceTypes.run(cache, {es_desired_data_instance_type: 't2.small.elasticsearch', es_desired_master_instance_type: 't2.small.elasticsearch'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no domain names found', function (done) {
            const cache = createCache([], []);
            esDesiredInstanceTypes.run(cache, {es_desired_data_instance_type: 't2.small.elasticsearch', es_desired_master_instance_type: 't2.small.elasticsearch'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error listing domain names', function (done) {
            const cache = createErrorCache();
            esDesiredInstanceTypes.run(cache, {es_desired_data_instance_type: 't2.small.elasticsearch', es_desired_master_instance_type: 't2.small.elasticsearch'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for domain names', function (done) {
            const cache = createNullCache();
            esDesiredInstanceTypes.run(cache, {es_desired_data_instance_type: 't2.small.elasticsearch', es_desired_master_instance_type: 't2.small.elasticsearch'}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should not return any results if settings are not provided', function (done) {
            const cache = createNullCache();
            esDesiredInstanceTypes.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
