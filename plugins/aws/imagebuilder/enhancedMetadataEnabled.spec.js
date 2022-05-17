var expect = require('chai').expect;;
var enhancedMetadataEnabled = require('./enhancedMetadataEnabled');

const listImagePipelines = [
    {
        "arn": "arn:aws:imagebuilder:us-east-1:000011112222:image-pipeline/akhtar-img-pipeline",
        "name": "akhtar-img-pipeline",
        "platform": "Linux",
        "enhancedImageMetadataEnabled": true,
        "imageRecipeArn": "arn:aws:imagebuilder:us-east-1:000011112222:image-recipe/akhtar-img-rc/1.0.0",
        "infrastructureConfigurationArn": "arn:aws:imagebuilder:us-east-1:000011112222:infrastructure-configuration/akhtar-img-pipeline-914d5fdf-45db-4231-ae0e-991c39f9e594",
        "distributionConfigurationArn": "arn:aws:imagebuilder:us-east-1:000011112222:distribution-configuration/akhtar-img-pipeline-914d5fdf-45db-4231-ae0e-991c39f9e594",
        "imageTestsConfiguration": {
            "imageTestsEnabled": true,
            "timeoutMinutes": 720
        },
        "status": "ENABLED",
        "dateCreated": "2022-03-08T11:20:43.395Z",
        "dateUpdated": "2022-03-08T11:20:43.395Z",
        "tags": {}
    },
    {
        "arn": "arn:aws:imagebuilder:us-east-1:000011112222:image-pipeline/akhtar-img-pipeline",
        "name": "akhtar-img-pipeline",
        "platform": "Linux",
        "enhancedImageMetadataEnabled": false,
        "imageRecipeArn": "arn:aws:imagebuilder:us-east-1:000011112222:image-recipe/akhtar-img-rc/1.0.0",
        "infrastructureConfigurationArn": "arn:aws:imagebuilder:us-east-1:000011112222:infrastructure-configuration/akhtar-img-pipeline-914d5fdf-45db-4231-ae0e-991c39f9e594",
        "distributionConfigurationArn": "arn:aws:imagebuilder:us-east-1:000011112222:distribution-configuration/akhtar-img-pipeline-914d5fdf-45db-4231-ae0e-991c39f9e594",
        "imageTestsConfiguration": {
            "imageTestsEnabled": true,
            "timeoutMinutes": 720
        },
        "status": "ENABLED",
        "dateCreated": "2022-03-08T11:20:43.395Z",
        "dateUpdated": "2022-03-08T11:20:43.395Z",
        "tags": {}
    }
];

const createCache = (images) => {
    return {
        imagebuilder: {
            listImagePipelines: {
                "us-east-1": {
                    data: images                
                }
            }
        }
    }
}

const createNullCache = () => {
    return {
        imagebuilder: {
            listImagePipelines: {
                "us-east-1": {
                    data: null
                }
            }
        }
    }
}

describe('enhancedMetadataEnabled', () => {
    describe('run', () => {
        it('should PASS if Image pipeline has enhanced metadata collection enabled', () => {
            const cache = createCache([listImagePipelines[0]]);
            enhancedMetadataEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Image pipeline has enhanced metadata collection enabled');
                expect(results[0].region).to.equal('us-east-1');
            })
        });
        it('should FAIL if Image pipeline does not have enhanced metadata collection enabled', () => {
            const cache = createCache([listImagePipelines[1]]);
            enhancedMetadataEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Image pipeline does not have enhanced metadata collection enabled');
                expect(results[0].region).to.equal('us-east-1');
            })
        });
        it('should PASS if No image pipeline list found', () => {
            const cache = createCache([]);
            enhancedMetadataEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Image Builder image pipelines found');
                expect(results[0].region).to.equal('us-east-1');
            })
        });
        it('should UNKNOWN if Unable to list image pipeline', () => {
            const cache = createNullCache();
            enhancedMetadataEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to list image pipeline');
                expect(results[0].region).to.equal('us-east-1');
            })
        });
        it('should not return anything if list image pipeline response is not found', () => {
            enhancedMetadataEnabled.run({}, {}, (err, results) => {
                expect(results.length).to.equal(0);
            })
        });
    });
});
