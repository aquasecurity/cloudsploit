var expect = require('chai').expect;
const customModelHasTags = require('./customModelHasTags');

const listCustomModels = [
    {
        "modelArn": "arn:aws:bedrock:us-east-1:11223344:custom-model/amazon.titan-text-lite-v1:0:4k/2ytyyx8nid0h",
        "modelName": "model2",
        "creationTime": "2023-11-29T10:45:43.056000+00:00",
        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1:0:4k",
        "baseModelName": ""
    },
    {
        "modelArn": "arn:aws:bedrock:us-east-1:11223344:custom-model/amazon.titan-text-lite-v1:0:4k/vjqsydtdhkpz",
        "modelName": "testmodel2",
        "creationTime": "2023-11-28T11:29:18.655000+00:00",
        "baseModelArn": "arn:aws:bedrock:us-east-1::foundation-model/amazon.titan-text-lite-v1:0:4k",
        "baseModelName": ""
    }
];

const getResources = [
    {
        "ResourceARN": "arn:aws:codestar:us-east-1:111222333444:project/aqua-project",
        "Tags": [],
    },
     {
        "ResourceARN": "arn:aws:bedrock:us-east-1:11223344:custom-model/amazon.titan-text-lite-v1:0:4k/2ytyyx8nid0h",
        "Tags": [{key: 'value'}],
    }
]


const createCache = (listModels, rgData) => {
    return {
        bedrock: {
            listCustomModels: {
                'us-east-1': {
                    err: null,
                    data: listModels
                }
            },
        },
        resourcegroupstaggingapi: {
            getResources: {
                'us-east-1':{
                    err: null,
                    data: rgData
                }
            }
        },
    };
};


describe('customModelHasTags', function () {
    describe('run', function () {
        it('should PASS if Bedrock custom model has tags', function (done) {
            const cache = createCache([listCustomModels[0]], [getResources[1]]);
            customModelHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Bedrock custom model has tags')
                done();
            });
        });

        it('should FAIL if Bedrock custom model doesnot have tags', function (done) {
            const cache = createCache([listCustomModels[0]], [getResources[0]]);
            customModelHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Bedrock custom model does not have any tags')
                done();
            });
        });

        it('should PASS if no Bedrock custom model found', function (done) {
            const cache = createCache([]);
            customModelHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No Bedrock custom model found')
                done();
            });
        });

        it('should UNKNOWN if unable to query Bedrock custom model', function (done) {
            const cache = createCache(null, null);
            customModelHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Bedrock custom model list')
                done();
            });
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const cache = createCache([listCustomModels[0]],null);
            customModelHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query all resources')
                done();
            });
        });
    });
});
