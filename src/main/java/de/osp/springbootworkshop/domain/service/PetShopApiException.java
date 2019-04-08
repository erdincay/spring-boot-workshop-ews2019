package de.osp.springbootworkshop.domain.service;

/**
 * @author Denny
 */
public abstract class PetShopApiException extends RuntimeException {
    public PetShopApiException(String message) {
        super(message);
    }

    public PetShopApiException(String message, Throwable cause) {
        super(message, cause);
    }

    public PetShopApiException(Throwable cause) {
        super(cause);
    }
}