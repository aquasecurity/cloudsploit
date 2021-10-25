var parse = function(obj, path) {
    if (typeof path == 'string') path = path.split('.');
    if (Array.isArray(path) && path.length) {
        var localPath = path.shift();
        if (localPath.includes('[*]')){
            localPath = localPath.split('[')[0];
            if (obj[localPath] && obj[localPath].length && obj[localPath].length === 1) {
                if (!path || !path.length) {
                    return [obj[localPath][0], path];
                } else if (path.length === 1){
                    return [obj[localPath][0][path[0]]];
                }
            }
            if (path.length && path.join('.').includes('[*]')) {
                return parse(obj[localPath], path);
            }
            return [obj[localPath], path];
        }
        if (obj[localPath] || typeof obj[localPath] === 'boolean') {
            return parse(obj[localPath], path);
        } else {
            return ['not set'];
        }
    } else if (Array.isArray(obj)) {
        return obj;
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
    let failingResults = [];
    let passingResults = [];
    inputResultsArr.forEach(localResult => {
        if (localResult.status === 2) {
            failingResults.push(localResult.message);
        }

        if (localResult.status === 0) {
            passingResults.push(localResult.message);
        }
    });

    if (!logical) {
        results.push({
            status: inputResultsArr[0].status,
            resource: resource,
            message: inputResultsArr[0].message,
            region: region
        });
    } else if (logical === 'AND') {
        if (failingResults && failingResults.length) {
            results.push({
                status: 2,
                resource: resource,
                message: failingResults.join(' and '),
                region: region
            });
        } else {
            results.push({
                status: 0,
                resource: resource,
                message: passingResults.join(' and '),
                region: region
            });
        }
    } else {
        if (passingResults && passingResults.length) {
            results.push({
                status: 0,
                resource: resource,
                message: passingResults.join(' and '),
                region: region
            });
        } else {
            results.push({
                status: 2,
                resource: resource,
                message: failingResults.join(' and '),
                region: region
            });
        }
    }
};

var validate = function(condition, conditionResult, inputResultsArr, message, property, parsed) {
    if (property.length){
        property = property[property.length-1];
    }
    if (parsed && typeof parsed === 'object' && parsed[property]) {
        condition.parsed = parsed[property];
    }

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
                    subProcessed.push(runValidation(parsed, condition, inputResultsArr));
                });
                subProcessed.forEach(function(sub) {
                    if (sub.status) conditionResult = sub.status;
                    if (sub.message) message.push(sub.message);
                });
            }
        } else if (condition.op == 'EQ') {
            if (condition.parsed == condition.value) {
                message.push(`${property}: ${condition.parsed} matched: ${condition.value}`);
                return 0;
            } else {
                message.push(`${property}: ${condition.parsed} did not match: ${condition.value}`);
                return 2;
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
                return 0;
            } else {
                message.push(`${property}: ${condition.parsed}`);
                return 2;
            }
        } else if (condition.op == 'ISTRUE') {
            if (typeof condition.parsed == 'boolean' && condition.parsed) {
                message.push(`${property} is true`);
                return 0;
            } else if (typeof condition.parsed == 'boolean' && !condition.parsed) {
                conditionResult = 2;
                message.push(`${property} is false`);
                return 2;
            } else {
                message.push(`${property} is not a boolean value`);
                return 2;
            }
        } else if (condition.op == 'ISFALSE') {
            if (typeof condition.parsed == 'boolean' && !condition.parsed) {
                message.push(`${property} is false`);
                return 0;
            } else if (typeof condition.parsed == 'boolean' && condition.parsed) {
                conditionResult = 2;
                message.push(`${property} is true`);
                return 2;
            } else {
                message.push(`${property} is not a boolean value`);
                return 2;
            }
        } else if (condition.op == 'CONTAINS') {
            if (condition.parsed && condition.parsed.length && condition.parsed.includes(condition.value)) {
                message.push(`${property}: ${condition.value} found in ${condition.parsed}`);
                return 0;
            } else if (condition.parsed && condition.parsed.length){
                message.push(`${condition.value} not found in ${condition.parsed}`);
                return 2;
            } else {
                message.push(`${condition.parsed} is not the right property type for this operation`);
                return 2;
            }
        }
        return conditionResult;
    }
};

var runValidation = function(obj, condition, inputResultsArr, nestedResultArr) {
    let result = 0;
    let message = [];

    // Extract the values for the conditions
    if (condition.property) {

        let conditionResult = 0;
        let property;
        if (condition.property.length === 1) property = condition.property[0];
        else if (condition.property.length > 1) property = condition.property.slice(0);
        condition.parsed = parse(obj, condition.property)[0];

        if ((typeof condition.parsed !== 'boolean' && !condition.parsed)|| condition.parsed === 'not set'){
            conditionResult = 2;
            message.push(`${property}: not set to any value`);

            let resultObj = {
                status: conditionResult,
                message: message.join(', ')
            };

            inputResultsArr.push(resultObj);
            return resultObj;
        }

        if (property.includes('[*]')) {
            if (Array.isArray(condition.parsed)) {
                if (!Array.isArray(nestedResultArr)) nestedResultArr = [];
                let propertyArr = property.split('.');
                propertyArr.shift();
                property = propertyArr.join('.');
                condition.property = property;
                condition.parsed.forEach(parsed => {
                    if (property.includes('[*]')) {
                        runValidation(parsed, condition, inputResultsArr, nestedResultArr);
                    } else {
                        let localConditionResult = validate(condition, conditionResult, inputResultsArr, message, property, parsed);
                        nestedResultArr.push(localConditionResult);
                    }
                    // [0,2,0,2,0,0,2,2]
                });
                // NestedCompositeResult
                if (nestedResultArr && nestedResultArr.length) {
                    if (!condition.nested) condition.nested = 'ONE';
                    let resultObj;
                    if ((condition.nested.toUpperCase() === 'ONE' && nestedResultArr.indexOf(0) > -1) || (condition.nested.toUpperCase() === 'ALL' && nestedResultArr.indexOf(2) === 0)) {
                        resultObj = {
                            status: 0,
                            message: message.join(', ')
                        };
                    } else {
                        resultObj = {
                            status: 2,
                            message: message.join(', ')
                        };
                    }

                    inputResultsArr.push(resultObj);
                    return resultObj;
                }
            } else {
                if (!Array.isArray(nestedResultArr)) nestedResultArr = [];
                let propertyArr = property.split('.');
                propertyArr.shift();
                property = propertyArr.join('.');
                let localConditionResult = validate(condition, conditionResult, inputResultsArr, message, condition.property, condition.parsed);

                let resultObj = {
                    status: localConditionResult,
                    message: message.join(', ')
                };


                inputResultsArr.push(resultObj);
                return resultObj;

            }
        } else {
            // Transform the property if required
            conditionResult = validate(condition, conditionResult, inputResultsArr, message, property);
            if (conditionResult) result = conditionResult;
        }
    }

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

var runConditions = function(input, data, results, resourcePath, resourceName, region) {
    let dataToValidate;
    let newPath;
    let newData;
    let validated;
    let parsedResource;

    let inputResultsArr = [];
    let logical;
    let localInput = JSON.parse(JSON.stringify(input));

    // to check if top level * matches. ex: Instances[*] should be
    // present in each condition if not its impossible to compare resources
    let resourceConditionArr = [];
    localInput.conditions.forEach(condition => {
        logical = condition.logical;
        var conditionPropArr = condition.property.split('.');
        if (condition.property && condition.property.includes('[*]')) {
            if (conditionPropArr.length > 1 && conditionPropArr[1].includes('[*]')) {
                resourceConditionArr.push(conditionPropArr[0]);
                var firstProperty = conditionPropArr.shift();
                dataToValidate = parse(data, firstProperty.split('[*]')[0]);
                condition.property = conditionPropArr.join('.');
                dataToValidate.forEach(newData => {
                    condition.validated = runValidation(newData, condition, inputResultsArr);
                    parsedResource = parse(newData, resourcePath)[0];
                    if (typeof parsedResource !== 'string') parsedResource = resourceName;
                });
                // result per resource
            } else {
                dataToValidate = parse(data, condition.property);
                newPath = dataToValidate[1];
                newData = dataToValidate[0];
                condition.property = newPath;
                if (newData.length){
                    newData.forEach(dataElm =>{
                        condition.validated = runValidation(dataElm, condition, inputResultsArr);
                        parsedResource = parse(dataElm, resourcePath)[0];
                        if (typeof parsedResource !== 'string') parsedResource = resourceName;
                    });

                } else {
                    condition.validated = runValidation(newData, condition, inputResultsArr);
                    parsedResource = parse(newData, resourcePath)[0];
                    if (typeof parsedResource !== 'string') parsedResource = resourceName;
                }
            }
        } else {
            dataToValidate = parse(data, condition.property);
            if (dataToValidate.length === 1) {
                validated = runValidation(data, condition, inputResultsArr);
                parsedResource = parse(data, resourcePath)[0];
                if (typeof parsedResource !== 'string') parsedResource = resourceName;
            } else {
                newPath = dataToValidate[1];
                newData = dataToValidate[0];
                condition.property = newPath;
                newData.forEach(element =>{
                    condition.validated = runValidation(element, condition, inputResultsArr);
                    parsedResource = parse(data, resourcePath)[0];
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

    compositeResult(inputResultsArr, parsedResource, region, results, logical);
};

var asl = function(source, input, resourceMap, callback) {
    if (!source || !input) return callback('No source or input provided');
    if (!input.apis || !input.apis[0]) return callback('No APIs provided for input');
    if (!input.conditions || !input.conditions.length) return callback('No conditions provided for input');

    let service = input.conditions[0].service;
    let api = input.conditions[0].api;
    let resourcePath;
    if (resourceMap &&
        resourceMap[service] &&
        resourceMap[service][api]) {
        resourcePath = resourceMap[service][api];
    }

    if (!source[service]) return callback(`Source data did not contain service: ${service}`);
    if (!source[service][api]) return callback(`Source data did not contain API: ${api}`);

    let results = [];
    for (let region in source[service][api]) {
        let regionVal = source[service][api][region];
        if (typeof regionVal !== 'object') continue;
        if (regionVal.err) {
            results.push({
                status: 3,
                message: regionVal.err.message || 'Error',
                region: region
            });
        } else if (regionVal.data && regionVal.data.length) {
            regionVal.data.forEach(function(regionData) {
                runConditions(input, regionData, results, resourcePath, '', region);
            });
        } else if (regionVal.data && Object.keys(regionVal.data).length) {
            runConditions(input, regionVal.data, results, resourcePath, '', region);
        } else {
            if (!Object.keys(regionVal).length || (regionVal.data && (!regionVal.data.length || !Object.keys(regionVal.data).length))) {
                results.push({
                    status: 0,
                    message: 'No resources found in this region',
                    region: region
                });
            } else {
                for (let resourceName in regionVal) {
                    let resourceObj = regionVal[resourceName];
                    if (resourceObj.err || !resourceObj.data) {
                        results.push({
                            status: 3,
                            resource: resourceName,
                            message: resourceObj.err.message || 'Error',
                            region: region
                        });
                    } else {
                        runConditions(input, resourceObj.data, results, resourcePath, resourceName, region);
                    }
                }
            }
        }
    }

    callback(null, results, source[service][api]);
};

module.exports = asl;