package gamecubeloader.common;

import static org.junit.Assert.*;
import org.junit.Test;

import ghidra.app.util.demangler.DemangledException;
import ghidra.app.util.demangler.DemangledObject;
import gamecubeloader.common.CodeWarriorDemangler;

public class CodeWarriorDemanglerTest {

    @Test
    public void test_tww_version_check() throws DemangledException {
        CodeWarriorDemangler demangler = new CodeWarriorDemangler();
        DemangledObject demangledObject = demangler.demangle("version_check__Fv");
        assertTrue(demangledObject.demangledNameSuccessfully());
        assertEquals("version_check", demangledObject.getName());
        assertEquals("__stdcall version_check(void)", demangledObject.getSignature());
        assertEquals("__stdcall version_check(void)", demangledObject.getSignature(false));
    }


    @Test
    public void test_tww_PrmAbstract() throws DemangledException {
        CodeWarriorDemangler demangler = new CodeWarriorDemangler();
        DemangledObject demangledObject = demangler.demangle("PrmAbstract<Q310daTagLight5Act_c5Prm_e>__5daObjFPC10fopAc_ac_cQ310daTagLight5Act_c5Prm_eQ310daTagLight5Act_c5Prm_e");
        assertTrue(demangledObject.demangledNameSuccessfully());
        assertEquals("PrmAbstract", demangledObject.getName());
        assertEquals("__thiscall daObj::PrmAbstract<daTagLight::Act_c::Prm_e>(fopAc_ac_c const *,daTagLight::Act_c::Prm_e,daTagLight::Act_c::Prm_e)", demangledObject.getSignature());
        assertEquals("__thiscall daObj::PrmAbstract<daTagLight::Act_c::Prm_e>(fopAc_ac_c const *,daTagLight::Act_c::Prm_e,daTagLight::Act_c::Prm_e)", demangledObject.getSignature(false));
    }
    
}
