package gamecubeloader.rel;

/**
 * Exception explaining that there was an error handling an REL file.
 */
public class InvalidRELException extends Exception {

    private static final long serialVersionUID = 1L;

    public InvalidRELException() {
        super();
    }

    public InvalidRELException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }

    public InvalidRELException(String message, Throwable cause) {
        super(message, cause);
    }

    public InvalidRELException(String message) {
        super(message);
    }

    public InvalidRELException(Throwable cause) {
        super(cause);
    }
    
}
