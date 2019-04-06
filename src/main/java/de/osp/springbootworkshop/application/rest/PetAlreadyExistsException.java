package de.osp.springbootworkshop.application.rest;

/**
 * @author Denny
 */
public class PetAlreadyExistsException extends PetShopApiException {
    public PetAlreadyExistsException(String message) {
        super(message);
    }

    public PetAlreadyExistsException(String message, Throwable cause) {
        super(message, cause);
    }

    public PetAlreadyExistsException(Throwable cause) {
        super(cause);
    }
}
