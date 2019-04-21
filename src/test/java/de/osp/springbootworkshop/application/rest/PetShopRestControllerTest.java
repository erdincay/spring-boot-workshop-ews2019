package de.osp.springbootworkshop.application.rest;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.osp.springbootworkshop.domain.model.Pet;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import java.math.BigDecimal;
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


/**
 * @author Denny
 */
@RunWith(SpringRunner.class)
@WebMvcTest(PetShopRestController.class)
public class PetShopRestControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private String toJSON(Object o) throws Exception {
        return objectMapper.writeValueAsString(o);
    }

    @Test
    public void testListPets() throws Exception {
        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.get("/petshop/pets")
                .accept(MediaType.APPLICATION_JSON_UTF8);
        mockMvc.perform(builder)
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8));
    }

    @Test
    public void testCreatePetWithInvalidRequest() throws Exception {
        Pet rex = new Pet("Rex", null, LocalDate.of(2018, 10, 13), BigDecimal.valueOf(750));

        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.post("/petshop/pets")
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_JSON)
                .characterEncoding("UTF-8")
                .content(toJSON(rex));
        mockMvc.perform(builder)
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8));
    }

    @Test
    public void testCreatePetWithValidRequest() throws Exception {
        Pet rex = new Pet("Rex", "Hund", LocalDate.of(2018, 10, 13), BigDecimal.valueOf(750));

        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.post("/petshop/pets")
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_JSON)
                .characterEncoding("UTF-8")
                .content(toJSON(rex));
        mockMvc.perform(builder)
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(content().json(toJSON(rex)));
    }

    @Test
    public void testDeletePetWithInvalidRequest() throws Exception {
        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.delete("/petshop/pets/{name}", "Unsinkable")
                .accept(MediaType.APPLICATION_JSON)
                .characterEncoding("UTF-8");
        mockMvc.perform(builder)
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8));
    }

    @Test
    public void testDeletePetWithValidRequest() throws Exception {
        MockHttpServletRequestBuilder builder = MockMvcRequestBuilders.delete("/petshop/pets/{name}", "Klaus")
                .accept(MediaType.APPLICATION_JSON)
                .characterEncoding("UTF-8");
        mockMvc.perform(builder)
                .andDo(print())
                .andExpect(status().isNoContent());
    }
}