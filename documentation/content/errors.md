---
weight: 20
title: Errors

---

# Errors

<aside class="notice">This error section is stored in a separate file, errors.md. DocuAPI allows you to split the single page documentation in as many files as needed. Files are included in the  default Hugo page order . One way of ordering the pages is by setting the page `weight` in the front matter. Pages with lower weight will be listed first.</aside>

The AuthBricks API uses the following error codes:

## 4xx

Error Code | Meaning
---------- | -------
400 | Bad Request -- The request was malformed or contained invalid parameters
401 | Unauthorized -- The request requires authentication
403 | Forbidden -- The authenticated user does not have permission to access the requested resource
404 | Not Found -- The requested resource could not be found
405 | Method Not Allowed -- The HTTP method is not supported for the requested resource
406 | Not Acceptable -- The requested response format is not supported
409 | Conflict -- The request conflicts with the current state of the resource
415 | Unsupported Media Type -- The request media type is not supported
429 | Too Many Requests -- The request rate limit has been exceeded

## 5xx

Error Code | Meaning
---------- | -------
500 | Internal Server Error -- An unexpected error occurred on the server
503 | Service Unavailable -- The service is temporarily unavailable