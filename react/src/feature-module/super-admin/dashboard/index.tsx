import { Link } from "react-router-dom";
import { all_routes } from "../../router/all_routes";
import CollapseHeader from "../../../core/common/collapse-header/collapse-header";
import ImageWithBasePath from "../../../core/common/imageWithBasePath";
import ReactApexChart from "react-apexcharts";
import { useDashboardData } from "../../../core/data/redux/useDashboardData";

const SuperAdminDashboard = () => {
  const routes = all_routes;
  const { dashboardData, loading, error, refetch } = useDashboardData();

  // Company chart configuration with dynamic data
  const getCompanyChart = () => ({
    chart: {
      height: 240,
      type: "bar" as const,
      toolbar: {
        show: false,
      },
    },
    colors: ["#212529"],
    responsive: [
      {
        breakpoint: 480,
        options: {
          legend: {
            position: "bottom",
            offsetX: -10,
            offsetY: 0,
          },
        },
      },
    ],
    plotOptions: {
      bar: {
        borderRadius: 10,
        borderRadiusWhenStacked: "all" as const,
        horizontal: false,
        endingShape: "rounded",
        colors: {
          backgroundBarColors: ["#f3f4f5"],
          backgroundBarOpacity: 0.5,
          hover: {
            enabled: true,
            borderColor: "#F26522",
          },
        },
      },
    },
    series: [
      {
        name: "Company",
        data:
          dashboardData.weeklyCompanies.length > 0
            ? dashboardData.weeklyCompanies
            : [0, 0, 0, 0, 0, 0, 0],
      },
    ],
    xaxis: {
      categories: ["M", "T", "W", "T", "F", "S", "S"],
      labels: {
        style: {
          colors: "#6B7280",
          fontSize: "13px",
        },
      },
    },
    yaxis: {
      labels: {
        offsetX: -15,
        show: false,
      },
    },
    grid: {
      borderColor: "#E5E7EB",
      strokeDashArray: 5,
      padding: {
        left: -8,
      },
    },
    legend: {
      show: false,
    },
    dataLabels: {
      enabled: false,
    },
    fill: {
      opacity: 1,
    },
  });

  // Revenue chart configuration with dynamic data
  const getRevenueChart = () => ({
    chart: {
      height: 230,
      type: "bar" as const,
      stacked: true,
      toolbar: {
        show: false,
      },
    },
    colors: ["#FF6F28", "#F8F9FA"],
    responsive: [
      {
        breakpoint: 480,
        options: {
          legend: {
            position: "bottom",
            offsetX: -10,
            offsetY: 0,
          },
        },
      },
    ],
    plotOptions: {
      bar: {
        borderRadius: 5,
        borderRadiusWhenStacked: "all" as const,
        horizontal: false,
        endingShape: "rounded",
      },
    },
    series: [
      {
        name: "Income",
        data:
          dashboardData.monthlyRevenue.income.length > 0
            ? dashboardData.monthlyRevenue.income
            : [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      },
      {
        name: "Expenses",
        data:
          dashboardData.monthlyRevenue.expenses.length > 0
            ? dashboardData.monthlyRevenue.expenses
            : [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      },
    ],
    xaxis: {
      categories: [
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
      ],
      labels: {
        style: {
          colors: "#6B7280",
          fontSize: "13px",
        },
      },
    },
    yaxis: {
      min: 0,
      max: 100,
      labels: {
        offsetX: -15,
        style: {
          colors: "#6B7280",
          fontSize: "13px",
        },
        formatter: (value: any) => {
          return `${value}K`;
        },
      },
    },
    grid: {
      borderColor: "transparent",
      strokeDashArray: 5,
      padding: {
        left: -8,
      },
    },
    legend: {
      show: false,
    },
    dataLabels: {
      enabled: false,
    },
    tooltip: {
      y: {
        formatter: (val: any) => `${val / 10} k`,
      },
    },
    fill: {
      opacity: 1,
    },
  });

  // Plan chart configuration with dynamic data
  const getPlanChart = () => {
    const planLabels =
      dashboardData.planDistribution.length > 0
        ? dashboardData.planDistribution.map((plan) => plan.name)
        : ["Basic", "Premium", "Enterprise"];

    const planSeries =
      dashboardData.planDistribution.length > 0
        ? dashboardData.planDistribution.map((plan) => plan.percentage)
        : [60, 20, 20];

    return {
      chart: {
        height: 240,
        type: "donut" as const,
        toolbar: {
          show: false,
        },
      },
      colors: ["#FFC107", "#1B84FF", "#F26522"],
      series: planSeries,
      labels: planLabels,
      plotOptions: {
        pie: {
          donut: {
            size: "50%",
            labels: {
              show: false,
            },
            borderRadius: 30,
          },
        },
      },
      stroke: {
        lineCap: "round" as const,
        show: true,
        width: 0,
        colors: ["#fff"],
      },
      dataLabels: {
        enabled: false,
      },
      legend: { show: false },
      responsive: [
        {
          breakpoint: 480,
          options: {
            chart: {
              height: 180,
            },
            legend: {
              position: "bottom",
            },
          },
        },
      ],
    };
  };

  return (
    <div className="page-wrapper">
      <div className="content">
        {/* Breadcrumb menu */}
        <div className="d-md-flex d-block align-items-center justify-content-between page-breadcrumb mb-3">
          <div className="my-auto mb-2">
            <h2 className="mb-1">Dashboard</h2>
            <nav>
              <ol className="breadcrumb mb-0">
                <li className="breadcrumb-item">
                  <Link to={routes.adminDashboard}>
                    <i className="ti ti-smart-home" />
                  </Link>
                </li>
                <li className="breadcrumb-item">Superadmin</li>
                <li className="breadcrumb-item active">
                  <Link to="#" aria-current="page">
                    Dashboard
                  </Link>
                </li>
              </ol>
            </nav>
          </div>
          <div className="d-flex my-xl-auto right-content align-items-center flex-wrap ">
            <div className="input-icon mb-2 position-relative">
              <span className="input-icon-addon">
                <i className="ti ti-calendar text-gray-9" />
              </span>
              <input
                type="text"
                className="form-control date-range bookingrange"
                placeholder="dd/mm/yyyy - dd/mm/yyyy"
              />
            </div>
            <div className="ms-2 head-icons">
              <CollapseHeader />
            </div>
          </div>
        </div>

        {/* /Breadcrumb */}
        {/* Welcome Wrap */}
        <div className="welcome-wrap mb-4">
          <div className=" d-flex align-items-center justify-content-between flex-wrap">
            <div className="mb-3">
              <h2 className="mb-1 text-white">Welcome Back, Super Admin</h2>
              {/* <p className="text-light">
                {loading
                  ? "Loading..."
                  : dashboardData.stats
                  ? `${dashboardData.stats.totalCompanies} Companies Registered`
                  : "Dashboard Ready"}
              </p> */}
            </div>
            <div className="d-flex align-items-center flex-wrap mb-1">
              <Link
                to={routes.superAdminCompanies}
                className="btn btn-dark btn-md me-2 mb-2"
              >
                Companies
              </Link>
              <Link
                to={routes.superAdminPackages}
                className="btn btn-light btn-md me-2 mb-2"
              >
                All Packages
              </Link>
              <button
                onClick={refetch}
                className="btn btn-outline-light btn-md mb-2"
                disabled={loading}
                type="button"
              >
                <i className="ti ti-refresh me-1" />
                {loading ? "Refreshing..." : "Refresh"}
              </button>
            </div>
          </div>
          <div className="welcome-bg">
            <ImageWithBasePath
              src="assets/img/bg/welcome-bg-02.svg"
              alt="img"
              className="welcome-bg-01"
            />
            <ImageWithBasePath
              src="assets/img/bg/welcome-bg-03.svg"
              alt="img"
              className="welcome-bg-02"
            />
            <ImageWithBasePath
              src="assets/img/bg/welcome-bg-01.svg"
              alt="img"
              className="welcome-bg-03"
            />
          </div>
        </div>

        {/* /Welcome Wrap */}
        {error && (
          <div
            className="alert alert-danger d-flex align-items-center"
            role="alert"
          >
            <i className="ti ti-alert-circle me-2" />
            <div>
              <strong>Error:</strong> {error}
              <button
                className="btn btn-sm btn-outline-danger ms-2"
                onClick={refetch}
                type="button"
              >
                Retry
              </button>
            </div>
          </div>
        )}

        <div className="row">
          {/* Total Companies */}
          <div className="col-xl-3 col-sm-6 d-flex">
            <div className="card flex-fill">
              <div className="card-body">
                <div className="d-flex align-items-center justify-content-between">
                  <span className="avatar avatar-md bg-dark mb-3">
                    <i className="ti ti-building fs-16" />
                  </span>
                  {/* <span className="badge bg-success fw-normal mb-3">
										+19.01%
									</span> */}
                </div>
                <div className="d-flex align-items-center justify-content-between">
                  <div>
                    <h2 className="mb-1">
                      {dashboardData.stats?.totalCompanies || 0}
                    </h2>
                    <p className="fs-13">Total Companies</p>
                  </div>
                  {/* <span className="text-success fs-14 fw-medium">
										{(dashboardData.stats?.totalCompanies || 0) > 0
											? "+19.01%"
											: "0%"}
									</span> */}
                </div>
              </div>
            </div>
          </div>

          {/* /Total Companies */}
          {/* Active Companies */}
          <div className="col-xl-3 col-sm-6 d-flex">
            <div className="card flex-fill">
              <div className="card-body">
                <div className="d-flex align-items-center justify-content-between">
                  <span className="avatar avatar-md bg-dark mb-3">
                    <i className="ti ti-carousel-vertical fs-16" />
                  </span>
                  {/* <span className="badge bg-danger fw-normal mb-3">-12%</span> */}
                </div>
                <div className="d-flex align-items-center justify-content-between">
                  <div>
                    <h2 className="mb-1">
                      {dashboardData.stats?.activeCompanies || 0}
                    </h2>
                    <p className="fs-13">Active Companies</p>
                  </div>
                  {/* <span className="text-danger fs-14 fw-medium">
										{(dashboardData.stats?.activeCompanies || 0) > 0
											? "-12%"
											: "0%"}
									</span> */}
                </div>
              </div>
            </div>
          </div>

          {/* /Active Companies */}
          {/* Total Subscribers */}
          <div className="col-xl-3 col-sm-6 d-flex">
            <div className="card flex-fill">
              <div className="card-body">
                <div className="d-flex align-items-center justify-content-between">
                  <span className="avatar avatar-md bg-dark mb-3">
                    <i className="ti ti-chalkboard-off fs-16" />
                  </span>
                  {/* <span className="badge bg-success fw-normal mb-3">
                    {(dashboardData.stats?.totalSubscribers || 0) > 0
                      ? "+6%"
                      : "0%"}
                  </span> */}
                </div>
                <div className="d-flex align-items-center justify-content-between">
                  <div>
                    <h2 className="mb-1">
                      {dashboardData.stats?.totalSubscribers || 0}
                    </h2>
                    <p className="fs-13">Total Subscribers</p>
                  </div>
                  {/* <span className="text-success fs-14 fw-medium">
                    {(dashboardData.stats?.totalSubscribers || 0) > 0
                      ? "+6%"
                      : "0%"}
                  </span> */}
                </div>
              </div>
            </div>
          </div>

          {/* /Total Subscribers */}
          {/* Total Earnings */}
          <div className="col-xl-3 col-sm-6 d-flex">
            <div className="card flex-fill">
              <div className="card-body">
                <div className="d-flex align-items-center justify-content-between">
                  <span className="avatar avatar-md bg-dark mb-3">
                    <i className="ti ti-businessplan fs-16" />
                  </span>
                  {/* <span className="badge bg-danger fw-normal mb-3">-16%</span> */}
                </div>
                <div className="d-flex align-items-center justify-content-between">
                  <div>
                    <h2 className="mb-1">
                      $
                      {dashboardData.stats?.totalEarnings?.toLocaleString() ||
                        0}
                    </h2>
                    <p className="fs-13">Total Earnings</p>
                  </div>
                  {/* <span className="text-danger fs-14 fw-medium">
                    {(dashboardData.stats?.totalEarnings || 0) > 0
                      ? "-16%"
                      : "0%"}
                  </span> */}
                </div>
              </div>
            </div>
          </div>

          {/* /Total Earnings */}
        </div>
        <div className="row">
          {/* Companies */}
          <div className="col-xxl-3 col-lg-6 d-flex">
            <div className="card flex-fill">
              <div className="card-header pb-2 d-flex align-items-center justify-content-between flex-wrap">
                <h5 className="mb-2">Companies</h5>
                <div className="dropdown mb-2">
                  <Link
                    to="#"
                    className="btn btn-white border btn-sm d-inline-flex align-items-center"
                    data-bs-toggle="dropdown"
                  >
                    <i className="ti ti-calendar me-1" />
                    This Week
                  </Link>
                  <ul className="dropdown-menu  dropdown-menu-end p-3">
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        This Month
                      </Link>
                    </li>
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        This Week
                      </Link>
                    </li>
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        Today
                      </Link>
                    </li>
                  </ul>
                </div>
              </div>
              <div className="card-body">
                <ReactApexChart
                  id="company-chart"
                  options={getCompanyChart()}
                  series={getCompanyChart().series}
                  type="bar"
                  height={240}
                />
                {/* <p className="f-13 d-inline-flex align-items-center">
                  <span className="badge badge-success me-1">+6%</span>
                  {dashboardData.stats?.totalCompanies || 0} Companies
                  registered
                </p> */}
              </div>
            </div>
          </div>

          {/* /Companies */}
          {/* Revenue */}
          <div className="col-lg-6 d-flex">
            <div className="card flex-fill">
              <div className="card-header pb-2 d-flex align-items-center justify-content-between flex-wrap">
                <h5 className="mb-2">Revenue</h5>
                <div className="dropdown mb-2">
                  <Link
                    to="#"
                    className="btn btn-white border btn-sm d-inline-flex align-items-center"
                    data-bs-toggle="dropdown"
                  >
                    <i className="ti ti-calendar me-1" />
                    2025
                  </Link>
                  <ul className="dropdown-menu  dropdown-menu-end p-3">
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        2024
                      </Link>
                    </li>
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        2025
                      </Link>
                    </li>
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        2023
                      </Link>
                    </li>
                  </ul>
                </div>
              </div>

              <div className="card-body pb-0">
                <div className="d-flex align-items-center justify-content-between flex-wrap">
                  <div className="mb-1">
                    <h5 className="mb-1">
                      $
                      {dashboardData.stats?.totalEarnings?.toLocaleString() ||
                        "0"}
                    </h5>
                    <p>
                      <span className="text-success fw-bold">+40%</span>{" "}
                      increased from last year
                    </p>
                  </div>
                  <p className="fs-13 text-gray-9 d-flex align-items-center mb-1">
                    <i className="ti ti-circle-filled me-1 fs-6 text-primary" />
                    Revenue
                  </p>
                </div>
                <ReactApexChart
                  id="revenue-income"
                  options={getRevenueChart()}
                  series={getRevenueChart().series}
                  type="bar"
                  height={230}
                />
              </div>
            </div>
          </div>

          {/* /Revenue */}
          {/* Top Plans */}
          <div className="col-xxl-3 col-xl-12 d-flex">
            <div className="card flex-fill">
              <div className="card-header pb-2 d-flex align-items-center justify-content-between flex-wrap">
                <h5 className="mb-2">Top Plans</h5>
                <div className="dropdown mb-2">
                  <Link
                    to="#"
                    className="btn btn-white border btn-sm d-inline-flex align-items-center"
                    data-bs-toggle="dropdown"
                  >
                    <i className="ti ti-calendar me-1" />
                    This Month
                  </Link>
                  <ul className="dropdown-menu  dropdown-menu-end p-3">
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        This Month
                      </Link>
                    </li>
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        This Week
                      </Link>
                    </li>
                    <li>
                      <Link to="#" className="dropdown-item rounded-1">
                        Today
                      </Link>
                    </li>
                  </ul>
                </div>
              </div>
              <div className="card-body">
                <ReactApexChart
                  options={getPlanChart()}
                  series={getPlanChart().series}
                  type="donut"
                  height={240}
                />
                {dashboardData.planDistribution.length > 0 ? (
                  dashboardData.planDistribution.map((plan, index) => {
                    const colorClasses = [
                      "text-warning",
                      "text-primary",
                      "text-info",
                    ];
                    const colorClass =
                      colorClasses[index % colorClasses.length];

                    return (
                      <div
                        key={plan.name}
                        className={`d-flex align-items-center justify-content-between ${
                          index < dashboardData.planDistribution.length - 1
                            ? "mb-2"
                            : "mb-0"
                        }`}
                      >
                        <p className="f-13 mb-0">
                          <i
                            className={`ti ti-circle-filled ${colorClass} me-1`}
                          />
                          {plan.name}
                        </p>
                        <p className="f-13 fw-medium text-gray-9">
                          {plan.percentage}%
                        </p>
                      </div>
                    );
                  })
                ) : (
                  <div className="text-center py-2">
                    <p className="text-muted f-13">No plan data available</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* /Top Plans */}
        </div>
        <div className="row">
          {/* Recent Transactions */}
          <div className="col-xxl-4 col-xl-12 d-flex">
            <div className="card flex-fill">
              <div className="card-header pb-2 d-flex align-items-center justify-content-between flex-wrap">
                <h5 className="mb-2">Recent Transactions</h5>
                <Link
                  to={routes.superAdminPurchaseTransaction}
                  className="btn btn-light btn-md mb-2"
                >
                  View All
                </Link>
              </div>
              <div className="card-body pb-2">
                {loading ? (
                  <div className="text-center py-4">
                    <div className="spinner-border text-primary" role="status">
                      <span className="visually-hidden">Loading...</span>
                    </div>
                  </div>
                ) : dashboardData.recentTransactions.length > 0 ? (
                  dashboardData.recentTransactions.map((transaction, index) => (
                    <div
                      key={transaction.id}
                      className={`d-sm-flex justify-content-between flex-wrap ${
                        index < dashboardData.recentTransactions.length - 1
                          ? "mb-3"
                          : "mb-1"
                      }`}
                    >
                      <div className="d-flex align-items-center mb-2">
                        <Link
                          to="#"
                          className="avatar avatar-md bg-gray-100 rounded-circle flex-shrink-0 d-flex align-items-center justify-content-center"
                          title={`View ${
                            transaction.company || "company"
                          } transaction`}
                          style={{
                            width: "48px",
                            height: "48px",
                            overflow: "hidden",
                          }}
                        >
                          <ImageWithBasePath
                            src={
                              transaction.logo && transaction.logo.trim() !== ""
                                ? transaction.logo
                                : "assets/img/company/company-02.svg"
                            }
                            isLink={Boolean(
                              transaction.logo?.startsWith("http")
                            )}
                            className="rounded-circle border"
                            width={48}
                            height={48}
                            alt={`${(transaction.company || "Company")
                              .substring(0, 2)
                              .toUpperCase()}`}
                          />
                        </Link>
                        <div className="ms-2 flex-fill">
                          <h6 className="fs-medium text-truncate mb-1">
                            <Link
                              to="#"
                              title={transaction.company || "Unknown Company"}
                            >
                              {transaction.company || "Unknown Company"}
                            </Link>
                          </h6>
                          <p className="fs-13 d-inline-flex align-items-center">
                            <span className="text-info fw-medium">
                              {transaction.transactionId || "#000000"}
                            </span>
                            <i className="ti ti-circle-filled fs-4 text-primary mx-1" />
                            <span className="text-muted">
                              {transaction.date || "Unknown Date"}
                            </span>
                          </p>
                        </div>
                      </div>
                      <div className="text-sm-end mb-2">
                        <h6 className="mb-1 text-success fw-medium">
                          {transaction.amount || "+$0"}
                        </h6>
                        <p className="fs-13 text-muted">
                          {transaction.plan || "Basic Plan"}
                        </p>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-4">
                    <p className="text-muted">No recent transactions found</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* /Recent Transactions */}
          {/* Recently Registered */}
          <div className="col-xxl-4 col-xl-6 d-flex">
            <div className="card flex-fill">
              <div className="card-header pb-2 d-flex align-items-center justify-content-between flex-wrap">
                <h5 className="mb-2">Recently Registered</h5>
                <Link
                  to={routes.superAdminPurchaseTransaction}
                  className="btn btn-light btn-md mb-2"
                >
                  View All
                </Link>
              </div>
              <div className="card-body pb-2">
                {loading ? (
                  <div className="text-center py-4">
                    <div className="spinner-border text-primary" role="status">
                      <span className="visually-hidden">Loading...</span>
                    </div>
                  </div>
                ) : dashboardData.recentlyRegistered.length > 0 ? (
                  dashboardData.recentlyRegistered.map((company, index) => (
                    <div
                      key={company.id}
                      className={`d-sm-flex justify-content-between flex-wrap ${
                        index < dashboardData.recentlyRegistered.length - 1
                          ? "mb-3"
                          : "mb-1"
                      }`}
                    >
                      <div className="d-flex align-items-center mb-2">
                        <Link
                          to="#"
                          className="avatar avatar-md bg-gray-100 rounded-circle flex-shrink-0"
                          title={`View ${company.name || "company"} details`}
                        >
                          <ImageWithBasePath
                            src={
                              company.logo && company.logo.trim() !== ""
                                ? company.logo
                                : "assets/img/icons/company-icon-11.svg"
                            }
                            isLink={Boolean(company.logo?.startsWith("http"))}
                            className="rounded-circle border"
                            width={48}
                            height={48}
                            alt={`${(company.name || "Company")
                              .substring(0, 2)
                              .toUpperCase()}`}
                          />
                        </Link>
                        <div className="ms-2 flex-fill">
                          <h6 className="fs-medium text-truncate mb-1">
                            <Link
                              to="#"
                              title={company.name || "Unknown Company"}
                            >
                              {company.name || "Unknown Company"}
                            </Link>
                          </h6>
                          <p className="fs-13 text-muted">
                            {company.plan || "Basic Plan"}
                          </p>
                        </div>
                      </div>
                      <div className="text-sm-end mb-2">
                        <p className="fs-13 mb-1 text-success fw-medium">
                          {company.users || 0} Users
                        </p>
                        <h6
                          className="fs-13 fw-normal text-info"
                          title={`Domain: ${company.domain}`}
                        >
                          {company.domain || "domain.example.com"}
                        </h6>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-4">
                    <p className="text-muted">
                      No recently registered companies found
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* /Recent Registered */}
          {/* Recent Plan Expired */}
          <div className="col-xxl-4 col-xl-6 d-flex">
            <div className="card flex-fill">
              <div className="card-header pb-2 d-flex align-items-center justify-content-between flex-wrap">
                <h5 className="mb-2">Recent Plan Expired</h5>
                <div className="dropdown mb-2">
                  <Link
                    to="#"
                    className="dropdown-toggle btn btn-white border btn-sm d-inline-flex align-items-center fs-13"
                    data-bs-toggle="dropdown"
                  >
                    Expired
                  </Link>
                  <div className="dropdown-menu dropdown-menu-end p-3">
                    <ul className="nav d-block">
                      <li>
                        <Link
                          to="#"
                          className="dropdown-item d-block rounded-1"
                          data-bs-toggle="tab"
                          data-bs-target="#expired"
                        >
                          Expired
                        </Link>
                      </li>
                      <li>
                        <Link
                          to="#"
                          className="dropdown-item d-block rounded-1"
                          data-bs-toggle="tab"
                          data-bs-target="#request"
                        >
                          Request
                        </Link>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
              <div className="card-body pb-2">
                <div className="tab-content">
                  <div className="tab-pane fade show active" id="expired">
                    {loading ? (
                      <div className="text-center py-4">
                        <div
                          className="spinner-border text-primary"
                          role="status"
                        >
                          <span className="visually-hidden">Loading...</span>
                        </div>
                      </div>
                    ) : dashboardData.expiredPlans.length > 0 ? (
                      dashboardData.expiredPlans.map((company, index) => (
                        <div
                          key={company.id}
                          className={`d-sm-flex justify-content-between flex-wrap ${
                            index < dashboardData.expiredPlans.length - 1
                              ? "mb-3"
                              : "mb-1"
                          }`}
                        >
                          <div className="d-flex align-items-center mb-2">
                            <Link
                              to="#"
                              className="avatar avatar-md bg-gray-100 rounded-circle flex-shrink-0 d-flex align-items-center justify-content-center"
                              title={`View ${
                                company.name || "company"
                              } details`}
                              style={{
                                width: "48px",
                                height: "48px",
                                overflow: "hidden",
                              }}
                            >
                              <ImageWithBasePath
                                src={
                                  company.logo && company.logo.trim() !== ""
                                    ? company.logo
                                    : "assets/img/icons/company-icon-16.svg"
                                }
                                isLink={Boolean(
                                  company.logo?.startsWith("http")
                                )}
                                className="rounded-circle border"
                                width={48}
                                height={48}
                                alt={`${(company.name || "Company")
                                  .substring(0, 2)
                                  .toUpperCase()}`}
                              />
                            </Link>
                            <div className="ms-2 flex-fill">
                              <h6 className="fs-medium text-truncate mb-1">
                                <Link
                                  to="#"
                                  title={company.name || "Unknown Company"}
                                >
                                  {company.name || "Unknown Company"}
                                </Link>
                              </h6>
                              <p className="fs-13 text-danger">
                                Expired: {company.expiredDate || "Unknown Date"}
                              </p>
                            </div>
                          </div>
                          <div className="text-sm-end mb-2">
                            <Link
                              to="#"
                              className="link-info text-decoration-underline d-block mb-1 fs-13"
                              title="Send renewal reminder email"
                            >
                              Send Reminder
                            </Link>
                            <p className="fs-13 text-muted">
                              {company.plan || "Basic Plan"}
                            </p>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-4">
                        <p className="text-muted">No expired plans found</p>
                      </div>
                    )}
                  </div>

                  <div className="tab-pane fade" id="request">
                    <div className="text-center py-4">
                      <div className="mb-3">
                        <i className="ti ti-clock-hour-3 fs-48 text-muted" />
                      </div>
                      <h6 className="text-muted">No Company Requests</h6>
                      <p className="text-muted fs-13">
                        Company registration requests will appear here when
                        available.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          {/* /Recent Plan Expired */}
        </div>
      </div>
      <div className="footer d-sm-flex align-items-center justify-content-between border-top bg-white p-3">
        <p className="mb-0">2014 - 2025 © Amasqis.</p>
        <p>
          Designed &amp; Developed By{" "}
          <Link to="#" className="text-primary">
            Dreams
          </Link>
        </p>
      </div>
    </div>
  );
};

export default SuperAdminDashboard;
