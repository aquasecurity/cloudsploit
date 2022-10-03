var expect = require('chai').expect;
var efsHasTags = require('./efsHasTags');

const createCache = (efsData) => {
    return {
        efs: {
            describeFileSystems: {
                'us-east-1': {
                    err: null,
                    data: efsData
                }
            }
        }
};
}

describe('efsHasTags', function () {
    describe('run', function () {

        it('should give passing result if no EFS file systems found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No EFS file systems present');
                done();
        };

            const cache = createCache([]);

            efsHasTags.run(cache, {}, callback);
        });

        it('shouldgive UNKNOWN result if unable to describe file systems', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for EFS file systems');
                done();
            };

            const cache = createCache(null);
            efsHasTags.run(cache, {}, callback);
        });

        it('should give failing result if EFS file systems have no tags', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('EFS file system does not have tags associated');
                done();
            };

            const cache = createCache([{  
                "OwnerId": "112233445566",
                "CreationToken": "console-c3581ec3-fc03-4a0e-924a-4bc09a4ec64e",
                "FileSystemId": "fs-61dff6e3",
                "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-61dff6e3",
                "CreationTime": "2020-10-18T18:55:19.000Z",
                "LifeCycleState": "available",
                "Name": null,
                "PerformanceMode": "generalPurpose",
                "Encrypted": true,
                "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/60c4f21b-e271-4e97-86ae-6403618a9467",
                "Tags": []
                }]);

            efsHasTags.run(cache, {}, callback);
        });

        it('should give passing results if EFS file systems have tags specified', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('EFS file system has tags')
                done()
            };

            const cache = createCache([{  
                "OwnerId": "112233445566",
                "CreationToken": "console-c3581ec3-fc03-4a0e-924a-4bc09a4ec64e",
                "FileSystemId": "fs-61dff6e3",
                "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:112233445566:file-system/fs-61dff6e3",
                "CreationTime": "2020-10-18T18:55:19.000Z",
                "LifeCycleState": "available",
                "Name": null,
                "PerformanceMode": "generalPurpose",
                "Encrypted": true,
                "KmsKeyId": "arn:aws:kms:us-east-1:112233445566:key/60c4f21b-e271-4e97-86ae-6403618a9467",
                "Tags": [{"Name": "TagName", "Value": "TagValue"}]
                }]);

            efsHasTags.run(cache, {}, callback);
        });
    });
});