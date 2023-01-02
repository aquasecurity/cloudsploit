var expect = require('chai').expect;
var secretHasTags = require('./secretHasTags');

const listSecrets = [
    {
        "ARN": "arn:aws:secretsmanager:us-east-1:111122223333:secret:secret-1-yfhuJM",
        "Name": "secret-1",
        "Description": "My DB secret",
        "KmsKeyId": "arn:aws:kms:us-east-1:111122223333:key/995d1b05-5f9c-4610-aae7-f8505f4458f5",
        "RotationEnabled": true,
        "RotationLambdaARN": "arn:aws:lambda:us-east-1:111122223333:function:test-lambda",
        "LastChangedDate": "2021-02-22T12:40:07.146Z",
        "Tags": [{key: 'value'}],
        "SecretVersionsToStages": {
            "56432b9d-8a51-43aa-b7f9-cac5470641d1": [
                "AWSCURRENT"
            ],
            "cbb8f659-cb58-41b4-ba2f-c5df8144086f": [
                "AWSPENDING"
            ]
        },
        "CreatedDate": "2021-02-22T12:29:25.488Z"
    },
    {
        "ARN": "arn:aws:secretsmanager:us-east-1:111122223333:secret:secret-1-yfhuJM",
        "Name": "secret-1",
        "Description": "My DB secret",
        "KmsKeyId": "arn:aws:kms:us-east-1:111122223333:key/995d1b05-5f9c-4610-aae7-f8505f4458f5",
        "RotationEnabled": false,
        "RotationLambdaARN": "arn:aws:lambda:us-east-1:111122223333:function:test-lambda",
        "LastChangedDate": "2021-02-22T12:40:07.146Z",
        "Tags": [],
        "SecretVersionsToStages": {
            "56432b9d-8a51-43aa-b7f9-cac5470641d1": [
                "AWSCURRENT"
            ],
            "cbb8f659-cb58-41b4-ba2f-c5df8144086f": [
                "AWSPENDING"
            ]
        },
        "CreatedDate": "2021-02-22T12:29:25.488Z"
    }
];


const createCache = (listSecrets, listErr) => {

    return {
        secretsmanager: {
            listSecrets: {
                'us-east-1': {
                    err: listErr,
                    data: listSecrets
                }
            },
        }
    };
};

const createNullCache = () => {
    return {
        secretsmanager: {
            listSecrets: {
                'us-east-1': null,
            }
        }
    };
};

describe('secretHasTags', function () {
    describe('run', function () {
        it('should PASS if secret has tags', function (done) {
            const cache = createCache([listSecrets[0]]);
            secretHasTags.run(cache, {},(err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Secrets Manager secret has tags');
                done();
            });
        });

        it('should FAIL if secret does not have tags', function (done) {
            const cache = createCache([listSecrets[1]]);
            secretHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Secrets Manager secret does not have tags');
                done();
            });
        });

        it('should PASS if no secrets found', function (done) {
            const cache = createCache([]);
            secretHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No secrets found');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for secrets', function (done) {
            const cache = createCache([],{ message: 'Unable to query secrets'});
            secretHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query for Secrets Manager secrets');
                done();
            });
        });
    });
});