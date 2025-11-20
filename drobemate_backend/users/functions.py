from rest_framework.response import Response

def api_response(success: bool, message: str, data=None, status_code=200):
    """
    Standardized API response for both success and error.

    Args:
        success (bool): True for success, False for error.
        message (str): Message describing the response.
        data (any, optional): Additional data to include.
        status_code (int, optional): HTTP status code (default 200).

    Returns:
        rest_framework.response.Response
    """
    return Response({
        "success": success,
        "message": message,
        "data": data
    }, status=status_code)
