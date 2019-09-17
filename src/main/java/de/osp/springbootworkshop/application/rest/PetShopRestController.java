package de.osp.springbootworkshop.application.rest;

import de.osp.springbootworkshop.domain.model.Pet;
import de.osp.springbootworkshop.domain.service.PetShopService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.constraints.NotNull;
import java.security.Principal;

/**
 * @author Denny
 */
@RestController
@RequestMapping("/petshop/pets")
public class PetShopRestController {
    private final PetShopService service;

    @Autowired
    public PetShopRestController(PetShopService service) {
        this.service = service;
    }

    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    public Iterable<Pet> listPets(Principal principal) {
        return service.listPets();
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public Pet createPet(@RequestBody @Validated @NotNull final Pet pet, Principal principal) {
       return service.createPet(pet);
    }

    @DeleteMapping("/{name}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void deletePet(@PathVariable @Validated @NotNull final String name, Principal principal) {
        service.deletePet(name);
    }
}
