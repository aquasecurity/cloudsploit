var expect = require('chai').expect;
var datasetExportEncrypted = require('./datasetExportEncrypted');

const listForecastExportJobs = [
    {
        "ForecastExportJobArn": "arn:aws:forecast:us-east-1:101363889637:forecast-export-job/akhtar_fc/ewd",
        "ForecastExportJobName": "ewd",
        "Destination": {
            "S3Config": {
                "Path": "s3://amazon-connect-5bc142a71067/data",
                "RoleArn": "arn:aws:iam::101363889637:role/service-role/AmazonForecast-ExecutionRole-1637334836508"
            }
        },
        "Status": "ACTIVE",
        "CreationTime": "2021-12-07T01:30:33.065000-08:00",
        "LastModificationTime": "2021-12-07T01:45:11.639000-08:00"
    },
    {
        "ForecastExportJobArn": "arn:aws:forecast:us-east-1:101363889637:forecast-export-job/akhtar_fc/samxbqwd",
        "ForecastExportJobName": "samxbqwd",
        "Destination": {
            "S3Config": {
                "Path": "s3://viteace-data-bucket/data",
                "RoleArn": "arn:aws:iam::101363889637:role/service-role/AmazonForecast-ExecutionRole-1637334836508",
                "KMSKeyArn": "arn:aws:kms:us-east-1:101363889637:key/ad013a33-b01d-4d88-ac97-127399c18b3e"
            }
        },
        "Status": "ACTIVE",
        "CreationTime": "2021-12-05T01:27:11.782000-08:00",
        "LastModificationTime": "2021-12-05T01:34:50.102000-08:00"
    }
];

const createCache = (forecastExportJobs) => {
    return {
        forecastservice: {
            listForecastExportJobs: {
                'us-east-1': {
                    err: null,
                    data: forecastExportJobs
                },
            }
        }
    };
};

describe('datasetExportEncrypted', function () {
    describe('run', function () {
        it('should PASS if Forecast Dataset Export is encrypted', function (done) {
            const cache = createCache([listForecastExportJobs[1]]);
            datasetExportEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Forecast Dataset Export is not encrypted', function (done) {
            const cache = createCache([listForecastExportJobs[0]]);
            datasetExportEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Forecast Dataset Export is found', function (done) {
            const cache = createCache([]);
            datasetExportEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Forecast Dataset Exports', function (done) {
            const cache = createCache(null, null, null);
            datasetExportEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
});
