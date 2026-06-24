// src/utils/errors.js
// M-10: Centralized error normalizer that maps server errors to safe UX messages
// Never exposes raw internal error strings (which may contain paths, stack traces,
// or DB error details) to the user.

const USER_MESSAGES = {
    400: 'Invalid request. Please check your input and try again.',
    401: 'Authentication required. Please log in again.',
    403: 'You do not have permission to perform this action.',
    404: 'The requested resource was not found.',
    409: 'A scan is already in progress.',
    413: 'Too many files. Please reduce the selection.',
    429: 'Too many requests. Please wait a moment and try again.',
    500: 'A server error occurred. Please try again.',
    502: 'Server is temporarily unavailable. Please try again.',
    503: 'Server is temporarily unavailable. Please try again.',
    default: 'An unexpected error occurred.',
};

export function toUserMessage(error) {
    // Network-level error (server unreachable, CORS, etc.)
    if (!error?.response) {
        return error?.code === 'ERR_NETWORK'
            ? 'Cannot reach the server. Check your connection.'
            : USER_MESSAGES.default;
    }

    // HTTP error from server — map status to safe message
    const status = error.response.status;
    return USER_MESSAGES[status] ?? USER_MESSAGES.default;
}
