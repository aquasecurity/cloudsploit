var expect = require('chai').expect;
var jobOutputsEncrypted = require('./jobOutputsEncrypted');

const listPipelines = [
    {
        "Id": "1636527154039-wkwqg1",
        "Arn": "arn:aws:elastictranscoder:us-east-1:000011112222:pipeline/1636527154039-wkwqg1",
        "Name": "aqua-pipeline",
        "Status": "Active",
        "InputBucket": "aquabucket",
        "OutputBucket": "aquabucket",
        "Role": "arn:aws:iam::000011112222:role/Elastic_Transcoder_Default_Role",
        "AwsKmsKeyArn": "arn:aws:kms:us-east-1:000011112222:key/c4750c1a-72e5-4d16-bc72-0e7b559e0250",
        "Notifications": {
            "Progressing": "",
            "Completed": "",
            "Warning": "",
            "Error": ""
        },
        "ContentConfig": {
            "Bucket": "aquabucket",
            "StorageClass": "Standard",
            "Permissions": [
                {
                    "GranteeType": "Canonical",
                    "Grantee": "000011112222",
                    "Access": [
                        "Read",
                        "ReadAcp",
                        "WriteAcp",
                        "FullControl"
                    ]
                }
            ]
        },
        "ThumbnailConfig": {
            "Bucket": "aquabucket",
            "StorageClass": "Standard",
            "Permissions": [
                {
                    "GranteeType": "Canonical",
                    "Grantee": "000011112222",
                    "Access": [
                        "Read",
                        "ReadAcp",
                        "WriteAcp",
                        "FullControl"
                    ]
                }
            ]
        }
    }
];

const listJobsByPipeline = [
    {
        "Id": "1636545275565-xwma1v",
        "Arn": "arn:aws:elastictranscoder:us-east-1:000011112222:job/1636545275565-xwma1v",
        "PipelineId": "1636530122589-ptkx1n",
        "Input": {
          "Key": "data/part-00000-5094adae-2612-4fd3-acfb-e6490cdc70e1-c000 (1).file",      
          "FrameRate": null,
          "Resolution": null,
          "AspectRatio": null,
          "Interlaced": null,
          "Container": null
        },
        "Inputs": [
          {
            "Key": "data/part-00000-5094adae-2612-4fd3-acfb-e6490cdc70e1-c000 (1).file",
            "FrameRate": null,
            "Resolution": null,
            "AspectRatio": null,
            "Interlaced": null,
            "Container": null
          }
        ],
        "Output": {
          "Id": "1",
          "Key": "file.mp4",
          "ThumbnailPattern": "",
          "Rotate": "auto",
          "PresetId": "1351620000001-000010",
          "SegmentDuration": null,
          "Status": "Error",
          "StatusDetail": "4000 92362f1a-fc60-4064-a219-a885d9e15bd2: Amazon Elastic Transcoder could not interpret the media file.",
          "Duration": null,
          "Width": null,
          "Height": null,
          "FrameRate": null,
          "FileSize": null,
          "DurationMillis": null,
          "Watermarks": [],
          "AppliedColorSpaceConversion": null
        },
        "Outputs": [
          {
            "Id": "1",
            "Key": "file.mp4",
            "ThumbnailPattern": "",
            "Rotate": "auto",
            "PresetId": "1351620000001-000010",
            "SegmentDuration": null,
            "Status": "Error",
            "StatusDetail": "4000 92362f1a-fc60-4064-a219-a885d9e15bd2: Amazon Elastic Transcoder could not interpret the media file.",
            "Duration": null,
            "Width": null,
            "Height": null,
            "FrameRate": null,
            "FileSize": null,
            "Encryption": {
                "Mode": "s3-aws-kms",
                "Key": null,
                "KeyMd5": null,
                "InitializationVector": null
            },
            "DurationMillis": null,
            "Watermarks": [],
            "AppliedColorSpaceConversion": null
          }
        ],
        "OutputKeyPrefix": "data/",
        "Playlists": [],
        "Status": "Progressing",
        "Timing": {
          "SubmitTimeMillis": 1636545275576,
          "StartTimeMillis": 1636545276637,
          "FinishTimeMillis": 1636545278699
        }
    },
    {
        "Id": "1636545275565-xwma1v",
        "Arn": "arn:aws:elastictranscoder:us-east-1:000011112222:job/1636545275565-xwma1v",
        "PipelineId": "1636530122589-ptkx1n",
        "Input": {
          "Key": "data/part-00000-5094adae-2612-4fd3-acfb-e6490cdc70e1-c000 (1).file",      
          "FrameRate": null,
          "Resolution": null,
          "AspectRatio": null,
          "Interlaced": null,
          "Container": null
        },
        "Inputs": [
          {
            "Key": "data/part-00000-5094adae-2612-4fd3-acfb-e6490cdc70e1-c000 (1).file",
            "FrameRate": null,
            "Resolution": null,
            "AspectRatio": null,
            "Interlaced": null,
            "Container": null
          }
        ],
        "Output": {
          "Id": "1",
          "Key": "file.mp4",
          "ThumbnailPattern": "",
          "Rotate": "auto",
          "PresetId": "1351620000001-000010",
          "SegmentDuration": null,
          "Status": "Error",
          "StatusDetail": "4000 92362f1a-fc60-4064-a219-a885d9e15bd2: Amazon Elastic Transcoder could not interpret the media file.",
          "Duration": null,
          "Width": null,
          "Height": null,
          "FrameRate": null,
          "FileSize": null,
          "DurationMillis": null,
          "Watermarks": [],
          "AppliedColorSpaceConversion": null
        },
        "Outputs": [
          {
            "Id": "1",
            "Key": "file.mp4",
            "ThumbnailPattern": "",
            "Rotate": "auto",
            "PresetId": "1351620000001-000010",
            "SegmentDuration": null,
            "Status": "Error",
            "StatusDetail": "4000 92362f1a-fc60-4064-a219-a885d9e15bd2: Amazon Elastic Transcoder could not interpret the media file.",
            "Duration": null,
            "Width": null,
            "Height": null,
            "FrameRate": null,
            "FileSize": null,
            "DurationMillis": null,
            "Watermarks": [],
            "AppliedColorSpaceConversion": null
          }
        ],
        "OutputKeyPrefix": "data/",
        "Playlists": [],
        "Status": "Progressing",
        "Timing": {
          "SubmitTimeMillis": 1636545275576,
          "StartTimeMillis": 1636545276637,
          "FinishTimeMillis": 1636545278699
        }
    },
    {
        "Id": "1636545275565-xwma1v",
        "Arn": "arn:aws:elastictranscoder:us-east-1:000011112222:job/1636545275565-xwma1v",
        "PipelineId": "1636530122589-ptkx1n",
        "Input": {
          "Key": "data/part-00000-5094adae-2612-4fd3-acfb-e6490cdc70e1-c000 (1).csv",      
          "FrameRate": null,
          "Resolution": null,
          "AspectRatio": null,
          "Interlaced": null,
          "Container": null
        },
        "Inputs": [
          {
            "Key": "data/part-00000-5094adae-2612-4fd3-acfb-e6490cdc70e1-c000 (1).csv",
            "FrameRate": null,
            "Resolution": null,
            "AspectRatio": null,
            "Interlaced": null,
            "Container": null
          }
        ],
        "Output": {
          "Id": "1",
          "Key": "file.mp4",
          "ThumbnailPattern": "",
          "Rotate": "auto",
          "PresetId": "1351620000001-000010",
          "SegmentDuration": null,
          "Status": "Error",
          "StatusDetail": "4000 92362f1a-fc60-4064-a219-a885d9e15bd2: Amazon Elastic Transcoder could not interpret the media file.",
          "Duration": null,
          "Width": null,
          "Height": null,
          "FrameRate": null,
          "FileSize": null,
          "DurationMillis": null,
          "Watermarks": [],
          "AppliedColorSpaceConversion": null
        },
        "Outputs": [
          {
            "Id": "1",
            "Key": "file.mp4",
            "ThumbnailPattern": "",
            "Rotate": "auto",
            "PresetId": "1351620000001-000010",
            "SegmentDuration": null,
            "Status": "Error",
            "StatusDetail": "4000 92362f1a-fc60-4064-a219-a885d9e15bd2: Amazon Elastic Transcoder could not interpret the media file.",
            "Duration": null,
            "Width": null,
            "Height": null,
            "FrameRate": null,
            "FileSize": null,
            "DurationMillis": null,
            "Watermarks": [],
            "AppliedColorSpaceConversion": null
          }
        ],
        "OutputKeyPrefix": "data/",
        "Playlists": [],
        "Status": "Error",
        "Timing": {
          "SubmitTimeMillis": 1636545275576,
          "StartTimeMillis": 1636545276637,
          "FinishTimeMillis": 1636545278699
        }
    }
];

const createCache = (pipelines, jobs, pipelinesErr, jobsErr) => {
    var pipelineId = (pipelines && pipelines.length) ? pipelines[0].Id : null;
    return {
        elastictranscoder: {
            listPipelines: {
                'us-east-1': {
                    err: pipelinesErr,
                    data: pipelines
                },
            },
            listJobsByPipeline: {
                'us-east-1': {
                    [pipelineId]: {
                        data: {
                            Jobs: jobs
                        },
                        err: jobsErr
                    }
                }
            }
        },
    };
};

describe('jobOutputsEncrypted', function () {
    describe('run', function () {
        it('should PASS if Elastic Transcoder pipeline has no jobs', function (done) {
            const cache = createCache(listPipelines, []);
            jobOutputsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if Elastic Transcoder pipeline job has encryption enabled for outputs', function (done) {
            const cache = createCache(listPipelines, [listJobsByPipeline[0]]);
            jobOutputsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if Elastic Transcoder pipeline job status is "Error"', function (done) {
            const cache = createCache(listPipelines, [listJobsByPipeline[2]]);
            jobOutputsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if Elastic Transcoder pipeline job does not encryption enabled for one or more outputs', function (done) {
            const cache = createCache(listPipelines, [listJobsByPipeline[1]]);
            jobOutputsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if no Elastic Transcoder pipelines found', function (done) {
            const cache = createCache([]);
            jobOutputsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to list Elastic Transcoder pipelines', function (done) {
            const cache = createCache(null, [], { message: "Unable to list Elastic Transcoder pipelines" });
            jobOutputsEncrypted.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
    });
}); 