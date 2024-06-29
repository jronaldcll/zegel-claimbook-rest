package com.zegel.claim_book.negocio;

import com.zegel.claim_book.entidades.Claimbook;
import com.zegel.claim_book.repositorio.ClaimbookRepositorio;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ClaimbookNegocio {
    @Autowired
    private ClaimbookRepositorio claimbookRepositorio;
    public Claimbook grabar(Claimbook claimbook){
        return claimbookRepositorio.save(claimbook);
    }
    public List<Claimbook> obtenerClaimbooks(){
        return (List<Claimbook>) claimbookRepositorio.findAll();
    }
    public Claimbook actualizar(Claimbook claimbook){
        Claimbook c = claimbookRepositorio.findById(claimbook.getIdClaim()).get();
        if(c!= null){
            return claimbookRepositorio.save(claimbook);
        }else {return null;}
    }
    public Claimbook borrarClaimbook(Long idClaim){
        Claimbook c = claimbookRepositorio.findById(idClaim).get();
        if(c!= null){
            claimbookRepositorio.delete(c);
        }else {return null;}
        return c;
    }

}
