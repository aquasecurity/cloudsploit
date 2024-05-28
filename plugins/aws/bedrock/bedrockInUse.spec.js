var expect = require('chai').expect;
const bedrockInUse = require('./bedrockInUse');

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


const createCache = (listModels) => {
    return {
        bedrock: {
            listCustomModels: {
                'us-east-1': {
                    err: null,
                    data: listModels
                }
            },
        }
    };
};


describe('bedrockInUse', function () {
    describe('run', function () {
        it('should PASS if Bedrock service is in use', function (done) {
            const cache = createCache([listCustomModels[0]]);
            bedrockInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Bedrock service is in use')
                done();
            });
        });

        it('should FAIL if Bedrock service is not in use', function (done) {
            const cache = createCache([]);
            bedrockInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Bedrock service is not in use')
                done();
            });
        });


        it('should UNKNOWN if unable to query Bedrock custom model', function (done) {
            const cache = createCache(null, null);
            bedrockInUse.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Bedrock custom model list')
                done();
            });
        });

    });
});
