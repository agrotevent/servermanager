import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(scope="session")
def data_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("smdata")
    os.environ["SM_CONFIG"] = str(d / "none.conf")
    os.environ["SM_DATA_DIR"] = str(d)
    from servermanager import config, core, security
    config.set_config(config.load_config())
    security.reset_key_cache()
    core._booted = False
    core.bootstrap()
    return d


@pytest.fixture(scope="session")
def app(data_dir):
    from servermanager.web import create_app
    return create_app(testing=True)


@pytest.fixture()
def db(data_dir):
    from servermanager.db import new_session
    s = new_session()
    yield s
    s.rollback()
    s.close()
