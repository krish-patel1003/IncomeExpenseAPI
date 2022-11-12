from rest_framework.views import exception_handler


def custom_exception_handler(exception, context):

    handlers = {
        'ValidationErrors': _handle_generic_error,
        'Http404': _handle_generic_error,
        'PermissionDenied': _handle_generic_error,
        'NotAuthenticated': _handle_authentication_error
    }


    response = exception_handler(exception, context)

    if response is not None:
        response.data['status_code'] = response.status_code

        if "AuthUserAPIView" in str(context['view']) and exception.status_code == 401:
            response.status_code = 200
            response.data = {
                'is_logged_in':False,
                'status_code':200
            }

            return response

        response.data['status_code'] = response.status_code

    exception_class = exception.__class__.__name__
    
    if exception_class in handlers:
        return handlers[exception_class](exception, context, response)


    return response 

def _handle_generic_error(exception, context, response):
    return response

def _handle_authentication_error(exception, context, response):
    
    response.data = {
        'error':"Please Login to continue",
        'status_code':response.status_code
    }

    return response


