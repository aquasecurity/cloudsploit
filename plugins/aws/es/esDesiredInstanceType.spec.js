const expect = require('chai').expect;
const esDesiredInstanceType = require('./esDesiredInstanceType');

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

describe('esDesiredInstanceType', function () {
    describe('run', function () {
        it('should FAIL if both dedicated master and data node desired instance types do not exist', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            esDesiredInstanceType.run(cache, {es_desired_data_instance_type: ['t2.medium.elasticsearch'], es_desired_master_instance_type: ['t2.medium.elasticsearch']}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });
        
        it('should PASS if desired instance types exist', function (done) {
            const cache = createCache([domainNames[0]], domains[1]);
            esDesiredInstanceType.run(cache, {es_desired_data_instance_type: ['t2.small.elasticsearch'], es_desired_master_instance_type: ['t2.small.elasticsearch']}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if either master or node desired instance type property do not exist ', function (done) {
            const cache = createCache([domainNames[0]], domains[1]);
            esDesiredInstanceType.run(cache, {es_desired_data_instance_type: ['t2.medium.elasticsearch'], es_desired_master_instance_type: ['t2.medium.elasticsearch']}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no domain names found', function (done) {
            const cache = createCache([], []);
            esDesiredInstanceType.run(cache, {es_desired_data_instance_type: ['t2.small.elasticsearch'], es_desired_master_instance_type: ['t2.small.elasticsearch']}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error listing domain names', function (done) {
            const cache = createErrorCache();
            esDesiredInstanceType.run(cache, {es_desired_data_instance_type: ['t2.small.elasticsearch'], es_desired_master_instance_type: ['t2.small.elasticsearch']}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for domain names', function (done) {
            const cache = createNullCache();
            esDesiredInstanceType.run(cache, {es_desired_data_instance_type: ['t2.small.elasticsearch'], es_desired_master_instance_type: ['t2.small.elasticsearch']}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should not return any results if settings are not provided', function (done) {
            const cache = createNullCache();
            esDesiredInstanceType.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
