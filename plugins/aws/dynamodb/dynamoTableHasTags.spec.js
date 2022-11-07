var expect = require('chai').expect;
var dynamoTable = require('./dynamoTableHasTags');

const createCache = (tableData, rgData) => {
    return {
        dynamodb: {
            listTables: {
                'us-east-1': {
                    err: null,
                    data: tableData
                }
            }
        },
        resourcegroupstaggingapi: {
            getResources: {
                'us-east-1':{
                    err: null,
                    data: rgData
                }
            }
        },
         sts: {
            getCallerIdentity: {
                'us-east-1': {
                    data: '1111222222222'
                }
            }
         }
    }
};

describe('dynamoTableHasTags', function () {
    describe('run', function () {
        it('should give unknown result if unable to list the dynamodb tables', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for DynamoDB tables');
                done();
            };

            const cache = createCache(
                null, []
            );

            dynamoTable.run(cache, {}, callback);
        });

        it('should give passing result if no dynamodb table found in region', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No DynamoDB tables found');
                done();
            };

            const cache = createCache(
                [], null
            );

            dynamoTable.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query all resources from group');
                done();
            };

            const cache = createCache(
                ['MyModelTypeTable'],
                null
            );

            dynamoTable.run(cache, {}, callback);
        });

        it('should give passing result if dynamoDB table has tags', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('DynamoDB table has tags');
                done();
            };

            const cache = createCache(
                ['MyModelTypeTable'],
                [{
                    "ResourceARN": "arn:aws:dynamodb:us-east-1:1111222222222:table/MyModelTypeTable",
                    "Tags": [{key:"key1", value:"value"}],
                }]
            );
            dynamoTable.run(cache, {}, callback);
        })

        it('should give failing result if dynamoDB table does not have tags', function (done) {
                const callback = (err, results) => {
                    expect(results.length).to.equal(1);
                    expect(results[0].status).to.equal(2);
                    expect(results[0].region).to.equal('us-east-1');
                    expect(results[0].message).to.include('DynamoDB table does not have any tags');
                    done();
                };

               const cache = createCache(
                ['MyModelTypeTable'],
                [{
                    "ResourceARN": "arn:aws:dynamodb:us-east-1:1111222222222:table/MyModelTypeTable",
                    "Tags": [],
                }]
            );

            dynamoTable.run(cache, {}, callback);
        });

    });
});
