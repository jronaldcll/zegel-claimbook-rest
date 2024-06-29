package com.zegel.claim_book.rest;

import com.zegel.claim_book.entidades.Claimbook;
import com.zegel.claim_book.negocio.ClaimbookNegocio;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/zegel")
public class servicioRest {
    @Autowired
    private ClaimbookNegocio claimbookNegocio;
    @PostMapping("/claimbook")
    public Claimbook grabar(@RequestBody Claimbook claimbook){
        return claimbookNegocio.grabar(claimbook);
    }
    @GetMapping("/claimbooks")
    public List<Claimbook> obtenerProductos(){
        try{
            return claimbookNegocio.obtenerClaimbooks();
        }
        catch (Exception e){
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No es posible obtener los datos");
        }
    }
    @PutMapping("/actualizar")
    public Claimbook actualizar(@RequestBody Claimbook claimbook){
        try{
            return claimbookNegocio.actualizar(claimbook);
        }
        catch (Exception e){
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No es posible actualizar");
        }
    }
    @DeleteMapping("/claimbook/{idClaim}")
    public Claimbook borrarClaimbook(@PathVariable(value = "idClaim") Long idClaim){
        return claimbookNegocio.borrarClaimbook(idClaim);
    }
}
