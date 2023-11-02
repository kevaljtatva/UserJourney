using System.Net;

namespace UserJourney.WebAPI.ResponseModel
{
    public class ApiResponse<T>
    {
        public HttpStatusCode StatusCode { get; set; } = HttpStatusCode.OK;
        public List<ApiMessage> Messages { get; set; } = new List<ApiMessage>();
        public bool Success { get; set; }
        public T Content { get; set; }
    }

    public class ApiMessage
    {
        public static class MessageTypes
        {
            public const string INFORMATION = "Information";
            public const string VALIDATION_ERROR = "Validation";
            public const string EXCEPTION = "Exception";
        }

        public string MessageType { get; set; }
        public string Message { get; set; }
    }

    public static class ApiMessageExtensions
    {
        public static ApiResponse<T> HandleException<T>(this ApiResponse<T> apiResponse, string exceptionMessage)
        {
            apiResponse.Success = false;
            apiResponse.StatusCode = HttpStatusCode.InternalServerError;
            apiResponse.Messages.Add(new ApiMessage()
            {
                MessageType = ApiMessage.MessageTypes.EXCEPTION,
                Message = exceptionMessage,
            });

            return apiResponse;
        }

        public static ApiResponse<T> HandleResponse<T>(this ApiResponse<T> apiResponse, T responseContent)
        {
            var statusCode = (int)apiResponse.StatusCode;
            apiResponse.Success = statusCode <= 400;
            apiResponse.StatusCode = apiResponse.StatusCode;
            apiResponse.Content = responseContent;
            return apiResponse;
        }
    }
}
