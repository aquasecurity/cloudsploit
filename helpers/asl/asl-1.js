var parse = function(obj, path) {
    if (typeof path == 'string') path = path.split('.');
    if (Array.isArray(path) && path.length) {
        var localPath = path.shift();
        if (localPath.includes('[*]')){
            localPath = localPath.split('[')[0];
            if (obj[localPath] && obj[localPath].length && obj[localPath].length === 1) return [obj[localPath][0], path];
            return [obj[localPath], path];
        }
        if (obj[localPath] || typeof obj[localPath] === 'boolean') {
            return parse(obj[localPath], path);
        } else {
            return ['not set'];
        }
    } else {
        return [obj];
    }
};

var transform = function(val, transformation) {
    if (transformation == 'DATE') {
        return new Date(val);
    } else if (transformation == 'INTEGER') {
        return parseInt(val);
    } else if (transformation == 'STRING') {
        return val.toString();
    } else if (transformation == 'DAYSFROM') {
        // Return the number of days between the date and now
        var now = new Date();
        var then = new Date(val);
        var timeDiff = then.getTime() - now.getTime();
        var diff = Math.abs(Math.round(timeDiff / (1000 * 3600 * 24)));
        return diff;
    } else if (transformation == 'COUNT') {
        return val.length;
    } else if (transformation == 'EACH') {
        return val;
    } else if (transformation == 'TOLOWERCASE') {
        return val.toLowerCase();
    } else {
        return val;
    }
};

var compositeResult = function(inputResultsArr, resource, region, results, logical) {
    if (!logical) {
        results.push({
            status: inputResultsArr[0].status,
            resource: resource,
            message: inputResultsArr[0].message,
            region: region
        });
    } else if (logical === 'AND') {
        var failingResult = inputResultsArr.find(localResult => {
            return localResult.status === 2;
        });

        if (failingResult) {
            results.push({
                status: failingResult.status,
                resource: resource,
                message: failingResult.message,
                region: region
            });
        } else {
            results.push({
                status: 0,
                resource: resource,
                message: 'All conditions passed',
                region: region
            });
        }
    } else {
        var passingResult = inputResultsArr.find(localResult => {
            return localResult.status === 0;
        });

        if (passingResult) {
            results.push({
                status: passingResult.status,
                resource: resource,
                message: passingResult.message,
                region: region
            });
        } else {
            results.push({
                status: 2,
                resource: resource,
                message: 'All conditions failed',
                region: region
            });
        }
    }
};

function evaluateCondition(obj, condition, inputResultsArr){
    let value = validate(obj,condition, inputResultsArr);
    return value;
}

var validate = function(obj, condition, inputResultsArr) {
    var result = 0;
    var message = [];
    var override = false;

    // Extract the values for the conditions
    if (condition.property) {
        var conditionResult = 0;
        var property;

        if (condition.property.length === 1) property = condition.property[0];
        else if (condition.property.length > 1) property = condition.property;

        condition.parsed = parse(obj, condition.property)[0];

        if (!condition.parsed || condition.parsed === 'not set'){
            conditionResult = 2;
            message.push(`${property}: not set to any value`);

            let resultObj = {
                status: conditionResult,
                message: message.join(', ')
            };

            inputResultsArr.push(resultObj);
            return resultObj;
        }

        // Transform the property if required
        if (condition.transform) {
            try {
                condition.parsed = transform(condition.parsed, condition.transform);
            } catch (e) {
                conditionResult = 2;
                message.push(`${property}: unable to perform transformation`);
                let resultObj = {
                    status: conditionResult,
                    message: message.join(', ')
                };

                inputResultsArr.push(resultObj);
                return resultObj;
            }
        }

        // Compare the property with the operator
        if (condition.op) {
            if (condition.transform && condition.transform == 'EACH' && condition) {
                // Recurse into the same function
                var subProcessed = [];
                if (!condition.parsed.length) {
                    conditionResult = 2;
                    message.push(`${property}: is not iterable using EACH transformation`);
                } else {
                    condition.parsed.forEach(function(parsed) {
                        subProcessed.push(validate(parsed, condition, inputResultsArr));
                    });
                    subProcessed.forEach(function(sub) {
                        if (sub.status) conditionResult = sub.status;
                        if (sub.message) message.push(sub.message);
                    });
                }
            } else if (condition.op == 'EQ') {
                if (condition.parsed == condition.value) {
                    message.push(`${property}: ${condition.parsed} matched: ${condition.value}`);
                } else {
                    conditionResult = 2;
                    message.push(`${property}: ${condition.parsed} did not match: ${condition.value}`);
                }
            } else if (condition.op == 'GT') {
                if (condition.parsed > condition.value) {
                    message.push(`${property}: count of ${condition.parsed} was greater than: ${condition.value}`);
                } else {
                    conditionResult = 2;
                    message.push(`${property}: count of ${condition.parsed} was not greater than: ${condition.value}`);
                }
            } else if (condition.op == 'NE') {
                if (condition.parsed !== condition.value) {
                    message.push(`${property}: ${condition.parsed} is not: ${condition.value}`);
                } else {
                    conditionResult = 2;
                    message.push(`${property}: ${condition.parsed} is: ${condition.value}`);
                }
            } else if (condition.op == 'MATCHES') {
                var userRegex = RegExp(condition.value);
                if (userRegex.test(condition.parsed)) {
                    message.push(`${property}: ${condition.parsed} matches the regex: ${condition.value}`);
                } else {
                    conditionResult = 2;
                    message.push(`${property}: ${condition.parsed} does not match the regex: ${condition.value}`);
                }
            } else if (condition.op == 'EXISTS') {
                if (condition.parsed !== 'not set') {
                    message.push(`${property}: set to ${condition.parsed}`);
                } else {
                    conditionResult = 2;
                    message.push(`${property}: ${condition.parsed}`);
                }
            } else if (condition.op == 'ISTRUE') {
                if (typeof condition.parsed == 'boolean' && condition.parsed) {
                    message.push(`${property} is true`);
                } else if (typeof condition.parsed == 'boolean' && !condition.parsed) {
                    conditionResult = 2;
                    message.push(`${property} is false`);
                } else {
                    conditionResult = 2;
                    message.push(`${property} is not a boolean value`);
                }
            } else if (condition.op == 'ISFALSE') {
                if (typeof condition.parsed == 'boolean' && !condition.parsed) {
                    message.push(`${property} is false`);
                } else if (typeof condition.parsed == 'boolean' && condition.parsed) {
                    conditionResult = 2;
                    message.push(`${property} is true`);
                } else {
                    conditionResult = 2;
                    message.push(`${property} is not a boolean value`);
                }
            } else if (condition.op == 'CONTAINS') {
                if (condition.parsed && condition.parsed.length && condition.parsed.includes(condition.value)) {
                    message.push(`${property}: ${condition.value} found in ${condition.parsed}`);
                } else if (condition.parsed && condition.parsed.length){
                    conditionResult = 2;
                    message.push(`${condition.value} not found in ${condition.parsed}`);
                } else {
                    conditionResult = 2;
                    message.push(`${condition.parsed} is not the right property type for this operation`);
                }
            }
        }

        if (condition.invert) conditionResult = (conditionResult ? 0 : 2);

        if (condition.override && !conditionResult) override = true;
        if (conditionResult) result = conditionResult;
    }


    if (result && override) result = 0;

    if (!message.length) {
        message = ['The resource matched all required conditions'];
    }

    let resultObj = {
        status: result,
        message: message.join(', ')
    };

    inputResultsArr.push(resultObj);
    return resultObj;
};

var asl = function(source, input, resourceMap, callback) {
    if (!source || !input) return callback('No source or input provided');
    if (!input.apis || !input.apis[0]) return callback('No APIs provided for input');
    if (!input.conditions || !input.conditions.length) return callback('No conditions provided for input');

    var service = input.conditions[0].service;
    var api = input.conditions[0].api;
    var resourcePath;
    if (resourceMap &&
        resourceMap[service] &&
        resourceMap[service][api]) {
        resourcePath = resourceMap[service][api];
    }

    if (!source[service]) return callback(`Source data did not contain service: ${service}`);
    if (!source[service][api]) return callback(`Source data did not contain API: ${api}`);

    var results = [];
    var dataToValidate;
    var newData;
    var newPath;
    var validated;
    var parsedResource;

    for (var region in source[service][api]) {
        var regionVal = source[service][api][region];
        if (typeof regionVal !== 'object') continue;
        if (regionVal.err) {
            results.push({
                status: 3,
                message: regionVal.err.message || 'Error',
                region: region
            });
        } else if (regionVal.data && regionVal.data.length) {
            if (!regionVal.data.length) {
                results.push({
                    status: 0,
                    message: 'No resources found in this region',
                    region: region
                });
            } else {
                regionVal.data.forEach(function(regionData) {
                    dataToValidate = parse(regionData, input.conditions.property);
                    var inputResultsArr = [];
                    var logical;
                    var localInput = JSON.parse(JSON.stringify(input));
                    localInput.conditions.forEach(condition => {
                        logical = condition.logical;
                        if (dataToValidate.length === 1) {
                            validated = evaluateCondition(regionData, condition, inputResultsArr);
                            parsedResource = parse(regionData, resourcePath)[0];
                            if (typeof parsedResource !== 'string') parsedResource = null;

                        } else {
                            newPath = dataToValidate[1];
                            newData = dataToValidate[0];
                            condition.property = newPath;
                            newData.forEach(element => {
                                validated = evaluateCondition(element, condition, inputResultsArr);
                                parsedResource = parse(newData, resourcePath)[0];
                                if (typeof parsedResource !== 'string') parsedResource = null;

                            });
                        }
                    });
                    compositeResult(inputResultsArr, parsedResource, region, results, logical);
                });
            }
        } else if (regionVal.data && Object.keys(regionVal.data).length > 0) {
            dataToValidate = parse(regionVal.data, input.conditions.property);
            let inputResultsArr = [];
            let logical;
            let localInput = JSON.parse(JSON.stringify(input));
            localInput.conditions.forEach(condition => {
                logical = condition.logical;
                if (dataToValidate.length === 1) {
                    validated = evaluateCondition(regionVal.data, condition, inputResultsArr);
                    parsedResource = parse(regionVal.data, resourcePath)[0];
                    if (typeof parsedResource !== 'string') parsedResource = null;

                } else {
                    newPath = dataToValidate[1];
                    newData = dataToValidate[0];
                    condition.property = newPath;
                    newData.forEach(element => {
                        validated = evaluateCondition(element, condition, inputResultsArr);
                        parsedResource = parse(newData, resourcePath)[0];
                        if (typeof parsedResource !== 'string') parsedResource = null;

                    });
                }
            });
            compositeResult(inputResultsArr, parsedResource, region, results, logical);

        } else {
            if (!Object.keys(regionVal).length) {
                results.push({
                    status: 0,
                    message: 'No resources found in this region',
                    region: region
                });
            } else {
                for (var resourceName in regionVal) {
                    var resourceObj = regionVal[resourceName];
                    if (resourceObj.err) {
                        results.push({
                            status: 3,
                            resource: resourceName,
                            message: resourceObj.err.message || 'Error',
                            region: region
                        });
                    } else if (!resourceObj.data) {
                        results.push({
                            status: 3,
                            resource: resourceName,
                            message: 'No data returned',
                            region: region
                        });
                    } else {
                        var inputResultsArr = [];
                        var logical;
                        var localInput = JSON.parse(JSON.stringify(input));
                        localInput.conditions.forEach(condition => {
                            logical = condition.logical;
                            if (condition.property && condition.property.indexOf('[*]') > -1) {
                                dataToValidate = parse(resourceObj.data, condition.property);
                                newPath = dataToValidate[1];
                                newData = dataToValidate[0];
                                condition.property = newPath;

                                condition.validated = evaluateCondition(newData, condition, inputResultsArr);
                                parsedResource = parse(resourceObj.data, resourcePath)[0];
                                if (typeof parsedResource !== 'string') parsedResource = null;
                            } else {
                                dataToValidate = parse(resourceObj.data, condition.property);
                                if (dataToValidate.length === 1) {
                                    validated = evaluateCondition(resourceObj.data, condition, inputResultsArr);
                                    parsedResource = parse(resourceObj.data, resourcePath)[0];
                                    if (typeof parsedResource !== 'string') parsedResource = null;
                                } else {
                                    newPath = dataToValidate[1];
                                    newData = dataToValidate[0];
                                    condition.property = newPath;
                                    newData.forEach(element =>{
                                        condition.validated = evaluateCondition(element, condition, inputResultsArr);
                                        parsedResource = parse(resourceObj.data, resourcePath)[0];
                                        if (typeof parsedResource !== 'string') parsedResource = null;

                                        results.push({
                                            status: validated.status,
                                            resource: parsedResource ? parsedResource : resourceName,
                                            message: validated.message,
                                            region: region
                                        });
                                    });
                                }
                            }
                        });
                        console.log(inputResultsArr);
                        compositeResult(inputResultsArr, parsedResource ? parsedResource : resourceName, region, results, logical);
                    }
                }
            }
        }
    }

    callback(null, results, source[service][api]);
};

module.exports = asl;