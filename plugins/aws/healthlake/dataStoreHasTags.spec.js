var expect = require('chai').expect;
const dataStoreHasTags = require('./dataStoreHasTags');

const listFHIRDatastores = [
    {
        "DatastoreId": "7ad17b6c9d48056865a8800b86cc2797",
        "DatastoreArn": "arn:aws:healthlake:us-east-1:000111222333:datastore/fhir/7ad17b6c9d48056865a8800b86cc2797",   
        "DatastoreName": "sadeed-ds1",
        "DatastoreStatus": "ACTIVE",
        "CreatedAt": "2021-11-23T15:31:55.180000+05:00",
        "DatastoreTypeVersion": "R4",
        "DatastoreEndpoint": "https://healthlake.us-east-1.amazonaws.com/datastore/7ad17b6c9d48056865a8800b86cc2797/r4/",
        "SseConfiguration": {
            "KmsEncryptionConfig": {
                "CmkType": "CUSTOMER_MANAGED_KMS_KEY",
                "KmsKeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
            }
        }
    },
    {
        "DatastoreId": "7ad17b6c9d48056865a8800b86cc2797",
        "DatastoreArn": "arn:aws:healthlake:us-east-1:000111222333:datastore/fhir/7ad17b6c9d48056865a880",   
        "DatastoreName": "sadeed-ds1",
        "DatastoreStatus": "ACTIVE",
        "CreatedAt": "2021-11-23T15:31:55.180000+05:00",
        "DatastoreTypeVersion": "R4",
        "DatastoreEndpoint": "https://healthlake.us-east-1.amazonaws.com/datastore/7ad17b6c9d48056865a8800b86cc2797/r4/",
        "SseConfiguration": {
            "KmsEncryptionConfig": {
                "CmkType": "CUSTOMER_MANAGED_KMS_KEY",
                "KmsKeyId": "arn:aws:kms:us-east-1:000111222333:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
            }
        }
    },
];

const getResources = [
    {
        "ResourceARN": "arn:aws:healthlake:us-east-1:000111222333:datastore/fhir/7ad17b6c9d48056865a880",
        "Tags": [],
    },
     {
        "ResourceARN": "arn:aws:healthlake:us-east-1:000111222333:datastore/fhir/7ad17b6c9d48056865a8800b86cc2797",
        "Tags": [{key: 'value'}],
    }
]


const createCache = (datastore, rgData) => {
    return {
        healthlake: {
            listFHIRDatastores: {
                'us-east-1': {
                    err: null,
                    data: datastore
                },
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


describe('dataStoreHasTags', function () {
    describe('run', function () {
        it('should PASS if Bedrock custom model has tags', function (done) {
            const cache = createCache([listFHIRDatastores[0]], [getResources[1]]);
            dataStoreHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Healthlake data store has tags')
                done();
            });
        });

        it('should FAIL if Bedrock custom model doesnot have tags', function (done) {
            const cache = createCache([listFHIRDatastores[0]], [getResources[0]]);
            dataStoreHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Healthlake data store does not have any tags')
                done();
            });
        });

        it('should PASS if no Bedrock custom model found', function (done) {
            const cache = createCache([]);
            dataStoreHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No HealthLake data stores found');
                done();
            });
        });

        it('should UNKNOWN if unable to query Bedrock custom model', function (done) {
            const cache = createCache(null, null);
            dataStoreHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query HealthLake Data Store: ')
                done();
            });
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const cache = createCache([listFHIRDatastores[0]],null);
            dataStoreHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query all resources')
                done();
            });
        });
    });
});
