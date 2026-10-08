import pytest
from iti.services import Service
from iti.store import Store
@pytest.fixture
def service(tmp_path):return Service(Store(tmp_path/'data'))
@pytest.fixture
def assessed(service):
    j=service.submit('fictional-bank','windows-ad','replay','case','activemq-derived',background=False)
    assert j['state']=='complete',j['data'].get('error')
    return service.store.get('assessment',j['data']['assessment_id'])
