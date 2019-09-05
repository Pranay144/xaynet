from xain.benchmark.net import model_fns
from xain.datasets.dataset import config

from .benchmark import aggregations, benchmarks


def test_valid_aggregation_names():
    """
    Verify that all aggregation names used in `Benchmark` objects are available in `aggregations`
    """

    # Prepare
    aggregation_names = [benchmarks[b].aggregation_name for b in benchmarks]

    # Assert
    for aggregation_name in aggregation_names:
        assert aggregation_name in aggregations


def test_valid_model_names():
    """
    Verify that all model names used in `Task` objects are available in `model_fns`
    """

    # Prepare
    model_names = [task.model_name for b in benchmarks for task in benchmarks[b].tasks]

    # Assert
    for model_name in model_names:
        assert model_name in model_fns


def test_valid_dataset_names():
    """
    Verify that all dataset names used in `Task` objects are available in `xain.datasets`
    """

    # Prepare
    dataset_names = [
        task.dataset_name for b in benchmarks for task in benchmarks[b].tasks
    ]
    all_datasets = config.keys()

    # Assert
    for dataset_name in dataset_names:
        assert dataset_name in all_datasets