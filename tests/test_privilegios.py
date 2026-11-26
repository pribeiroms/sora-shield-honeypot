from sora_shield.utils.privilegios import aviso_de_privilegio, e_administrador


def test_aviso_so_aparece_sem_privilegio():
    if e_administrador():
        assert aviso_de_privilegio() is None
    else:
        aviso = aviso_de_privilegio()
        assert "administrador" in aviso.lower() or "sudo" in aviso.lower()


def test_checagem_nunca_levanta():
    assert isinstance(e_administrador(), bool)