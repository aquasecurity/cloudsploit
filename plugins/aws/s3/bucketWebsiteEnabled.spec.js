var assert = require('assert');
var expect = require('chai').expect;
var s3 = require('./bucketWebsiteEnabled');

const createCache = (bucketErr, website, emptyBucket) => {
    var bucketObj = {};
    var bucketContents = [];
    if (bucketErr) {
        bucketObj = {
            "err": {
              "code": "NoSuchWebsiteConfiguration"
            }
        };
    } else if (website) {
        bucketObj = {
            "data": website
        };
    }

    if (!emptyBucket) {
      bucketContents.push({
        ETag: "\"70ee1738b6b21e2c8a43f3a5ab0eee71\"", 
        Key: "example1.jpg", 
        Size: 11, 
        StorageClass: "STANDARD"
      })
    }

    return {
      "s3": {
        "listBuckets": {
          "us-east-1": {
            "data": [
              {
                "Name": "bucket1"
              }
            ]
          }
        },
        "getBucketWebsite": {
          "us-east-1": {
            "bucket1": bucketObj
          }
        },
        "getBucketLocation": {
          'us-east-1': {
              "bucket1": {
                "data": {
                  "LocationConstraint": 'us-east-1'
              }
            }
          }
        },
        "listObjects": {
          "us-east-1": {
            "bucket1": {
              "data": bucketContents
            }
          }
        }
      }
    };
};

describe('bucketWebsiteEnabled', function () {
    describe('run', function () {
        it('should give passing result if S3 bucket has no website', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('does not have static website hosting enabled')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(true);

            s3.run(cache, {}, callback);
        })

        it('should give passing result if S3 bucket has no website config', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('does not have static website hosting enabled')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(false, {});

            s3.run(cache, {}, callback);
        })

        it('should give failing result if S3 bucket has website enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('has static website hosting enabled')
                expect(results[0].region).to.equal('us-east-1');
                done()
            };

            const cache = createCache(false, {
              "website": "config"
            });

            s3.run(cache, {}, callback);
        })

        it('should give passing result if S3 bucket is empty and whitelist s3 bucket setting is enabled', function (done) {
          const callback = (err, results) => {
              expect(results.length).to.equal(1)
              expect(results[0].status).to.equal(0)
              expect(results[0].message).to.include('is empty')
              expect(results[0].region).to.equal('us-east-1');
              done()
          };

          const cache = createCache(false, null, false);

          s3.run(cache, { s3_website_whitelist_empty_buckets: 'true' }, callback);
      })
    })
});