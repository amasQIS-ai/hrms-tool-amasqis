import React, { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { all_routes } from "../../router/all_routes";
import CollapseHeader from "../../../core/common/collapse-header/collapse-header";
import ImageWithBasePath from "../../../core/common/imageWithBasePath";
import CommonSelect from "../../../core/common/commonSelect";
import PredefinedDateRanges from "../../../core/common/datePicker";
import Table from "../../../core/common/dataTable/index";
import { package_list } from "../../../core/data/json/packagelist";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
import { useSocket } from "../../../SocketContext";
import Skeleton, { SkeletonTheme } from "react-loading-skeleton";
import "react-loading-skeleton/dist/skeleton.css";
import { planDetails } from "../../../core/data/json/planDetails";
import moment from "moment";
const Packages = () => {
  const [Data, setData] = useState([]);
  const [logo, setLogo] = useState(null); // To store the base64 image
  const [isLoading, setIsLoading] = useState(false);
  const [tempfiltereddata, settempfiltereddata] = useState(null);
  const [tableLoading, settableLoading] = useState(true);
  const fileInputRef = useRef(null);
  const [editmodelLoading, seteditmodelLoading] = useState(true);
  const [deleteLoader, setdeleteLoader] = useState(false);
  const socket = useSocket();
  const defaultAllTimeStart = moment.utc("1970-01-01T00:00:00Z").toISOString();
  const defaultAllTimeEnd = moment.utc().toISOString(); // Current UTC time
  const [filters, setFilters] = useState({
    planType: null, // 'Monthly' or 'Yearly'
    status: null, // 'Active' or 'Inactive'
    dateRange: {
      start: defaultAllTimeStart,
      end: defaultAllTimeEnd,
    },
  });

  useEffect(() => {
    if (filters && Data) {
      console.log("Filters updated:", filters);
      console.log("Data updated:", Data);
      let result = [...Data]; // Always start from the original Data

      // Apply filters
      if (filters.planType) {
        console.log(filters.planType);
        console.log(result);
        result = result.filter((plan) => plan.Plan_Type === filters.planType); // Removed curly braces
        console.log("FInallll---------->", result);
      }

      if (filters.status) {
        console.log(filters.status);
        console.log(result);
        result = result.filter((plan) => plan.Status === filters.status);
      }

      // Date Filtering
      if (filters.dateRange?.start || filters.dateRange?.end) {
        result = result.filter((plan) => {
          const planDate = new Date(plan.created_at);
          let start = filters.dateRange.start
            ? new Date(filters.dateRange.start)
            : null;
          let end = filters.dateRange.end
            ? new Date(filters.dateRange.end)
            : null;

          if (start) start.setHours(0, 0, 0, 0);
          if (end) end.setHours(23, 59, 59, 999);

          return (!start || planDate >= start) && (!end || planDate <= end);
        });
      }

      settempfiltereddata(result); // Store filtered data for reuse
    }
  }, [filters, Data]); // Removed tempfiltereddata from dependencies

  const columns = [
    {
      title: "",
      dataIndex: "id",
      key: "id",
      width: 0,
      responsive: ["xxl"], // Will never show on any screen
      render: () => null,
    },
    {
      title: "Plan Name",
      dataIndex: "Plan_Name",
      render: (text, record) => (
        <h6 className="fw-medium">
          <Link to="#">{text}</Link>
        </h6>
      ),
      sorter: (a, b) =>
        a.Plan_Name.toLowerCase().localeCompare(b.Plan_Name.toLowerCase()),
    },
    {
      title: "Plan Type",
      dataIndex: "Plan_Type",
      sorter: (a, b) => a.Plan_Type.length - b.Plan_Type.length,
    },
    {
      title: "Total Subscribers",
      dataIndex: "Total_Subscribers",
      sorter: (a, b) => a.Total_Subscribers < b.Total_Subscribers,
    },
    {
      title: "Price",
      dataIndex: "Price",
      sorter: (a, b) => a.Price < b.Price,
    },
    {
      title: "Created Date",
      dataIndex: "Created_Date",
      sorter: (a, b) => new Date(a.created_at) < new Date(b.created_at),
    },

    {
      title: "Status",
      dataIndex: "Status",
      render: (text, record) => (
        <span
          className={`badge ${
            text === "Active" ? "badge-success" : "badge-danger"
          } d-inline-flex align-items-center badge-xs`}
        >
          <i className="ti ti-point-filled me-1" />
          {text}
        </span>
      ),
      sorter: (a, b) => a.Status.length - b.Status.length,
    },
    {
      title: "",
      dataIndex: "actions",
      render: (_, record) => (
        <div className="action-icon d-inline-flex">
          <Link
            to="#"
            className="me-2"
            onClick={() => {
              Editplan(record.planid);
            }}
            data-bs-toggle="modal"
            data-bs-target="#edit_plans"
          >
            <i className="ti ti-edit" />
          </Link>
          <Link
            to="#"
            data-bs-toggle="modal"
            data-bs-target="#delete_modal"
            onClick={() => {
              setdeleteplan([record.planid]);
            }}
          >
            <i className="ti ti-trash" />
          </Link>
        </div>
      ),
    },
  ];
  const [deleteplan, setdeleteplan] = useState([]);
  const [resetKey, setResetKey] = useState(0);
  const [imageupload, setimageupload] = useState(false);

  const planName = [
    { value: "Advanced", label: "Advanced" },
    { value: "Basic", label: "Basic" },
    { value: "Enterprise", label: "Enterprise" },
  ];
  const planType = [
    { value: "Monthly", label: "Monthly" },
    { value: "Yearly", label: "Yearly" },
  ];
  const currency = [
    { value: "USD", label: "USD" },
    { value: "Euro", label: "Euro" },
  ];
  const planPosition = [
    { value: "1", label: "1" },
    { value: "2", label: "2" },
  ];
  const plancurrency = [
    { value: "Fixed", label: "Fixed" },
    { value: "Percentage", label: "Percentage" },
  ];
  const discountType = [
    { value: "Fixed", label: "Fixed" },
    { value: "Percentage", label: "Percentage" },
  ];
  const status = [
    { value: "Active", label: "Active" },
    { value: "Inactive", label: "Inactive" },
  ];

  const handleSelectChange = (name, selectedOption) => {
    setFormData((prevState) => ({
      ...prevState,
      [name]: selectedOption.value,
    }));
  };

  const handlePlanModulesChange = (e) => {
    const { name, checked } = e.target;
    setFormData((prevState) => ({
      ...prevState,
      planModules: {
        ...prevState.planModules,
        [name]: checked,
      },
    }));
  };

  const uploadImage = async (file) => {
    setLogo(null);
    const formData = new FormData();
    formData.append("file", file);
    formData.append("upload_preset", "amasqis"); // Replace with your Cloudinary Upload Preset

    const res = await fetch(
      "https://api.cloudinary.com/v1_1/dwc3b5zfe/image/upload",
      {
        method: "POST",
        body: formData,
      }
    );

    const data = await res.json();
    console.log(data);
    return data.secure_url; // This is the image URL to store in DB
  };

  const Editplan = (planid) => {
    reset_form();
    console.log(planid);
    seteditmodelLoading(true);
    socket.emit("superadmin/packages/get-plan", planid);
  };

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    const processedValue = type === "number" ? parseFloat(value) : value;

    setFormData((prevState) => ({
      ...prevState,
      [name]: type === "checkbox" ? checked : processedValue,
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (formData.planName.trim() === "") {
      toast.error("Enter Plan Name");
    }

    // Validate required fields
    const requiredFields = [
      { field: "planType", label: "Plan Type" },
      { field: "planPosition", label: "Plan Position" },
      { field: "planCurrency", label: "Plan Currency" },
      { field: "planCurrencytype", label: "Plan Currency Type" },
      { field: "status", label: "Status" },
      { field: "discountType", label: "Discount Type" },
    ];

    let hasError = false;

    requiredFields.forEach(({ field, label }) => {
      if (formData[field] === null) {
        toast.error(`Please select a value for ${label}.`, {
          position: "top-right",
          autoClose: 3000,
          hideProgressBar: true,
          closeOnClick: true,
          pauseOnHover: true,
          draggable: true,
        });
        hasError = true;
      }
    });

    // Stop submission if there are errors
    if (hasError) {
      setIsLoading(false); // Disable loading state
      return;
    }

    setIsLoading(true); // Enable loading state

    // Filter planModules to include only true values
    const filteredPlanModules = Object.keys(formData.planModules).filter(
      (key) => formData.planModules[key]
    ); // Keep only keys with true values

    console.log(filteredPlanModules); // Array of keys where value is true

    // Prepare the data to be submitted
    const formDataWithLogo = {
      ...formData,
      planModules: filteredPlanModules, // Replace planModules with the filtered object
      logo: logo, // Add the base64 image to the form data
    };

    // Emit the data via socket
    socket.emit("superadmin/packages/add-plan", formDataWithLogo);
  };
  const handleEditSubmit = async (e) => {
    e.preventDefault();

    // Validate required fields
    const requiredFields = [
      { field: "planType", label: "Plan Type" },
      { field: "planPosition", label: "Plan Position" },
      { field: "planCurrency", label: "Plan Currency" },
      { field: "planCurrencytype", label: "Plan Currency Type" },
      { field: "status", label: "Status" },
      { field: "discountType", label: "Discount Type" },
    ];

    let hasError = false;

    if (logo == null || logo == undefined || logo.trim() == "") {
      hasError = true;
      toast.error("Please upload a Logo.");
    }

    requiredFields.forEach(({ field, label }) => {
      if (formData[field] === null) {
        toast.error(`Please select a value for ${label}.`, {
          position: "top-right",
          autoClose: 3000,
          hideProgressBar: true,
          closeOnClick: true,
          pauseOnHover: true,
          draggable: true,
        });
        hasError = true;
      }
    });

    // Stop submission if there are errors
    if (hasError) {
      setIsLoading(false); // Disable loading state
      return;
    }

    setIsLoading(true); // Enable loading state

    // Filter planModules to include only true values
    const filteredPlanModules = Object.keys(formData.planModules).filter(
      (key) => formData.planModules[key]
    ); // Keep only keys with true values

    console.log(filteredPlanModules); // Array of keys where value is true

    // Prepare the data to be submitted
    const formDataWithLogo = {
      ...formData,
      planModules: filteredPlanModules, // Replace planModules with the filtered object
      logo: logo, // Add the base64 image to the form data
    };

    // Emit the data via socket
    socket.emit("superadmin/packages/update-plan", formDataWithLogo);
  };

  const reset_form = () => {
    setFormData({
      planName: "",
      planType: null,
      planPosition: null,
      planCurrency: null,
      planCurrencytype: null,
      discountType: null,
      discount: 0,
      limitationsInvoices: 0,
      maxCustomers: 0,
      price: "",
      product: 0,
      supplier: 0,
      planModules: {
        employees: false,
        invoices: false,
        reports: false,
        contacts: false,
        clients: false,
        estimates: false,
        goals: false,
        deals: false,
        projects: false,
        payments: false,
        assets: false,
        leads: false,
        tickets: false,
        taxes: false,
        activities: false,
        pipelines: false,
      },
      accessTrial: false,
      trialDays: 0,
      isRecommended: false,
      status: "Active",
      description: "",
    });
    RemoveLogo();
    setResetKey((prevKey) => prevKey + 1);
    const selectAllButton = document.getElementById("select-all-btn");
    selectAllButton.checked = false;
  };

  useEffect(() => {
    if (socket) {
      const handleAddResponse = (data) => {
        console.log("Response from server:", data);
        if (data.done) {
          setIsLoading(false);
          reset_form();
          document.getElementById("close-add-plan").click();
          toast.success("Plan added successfully!");
        } else {
          setIsLoading(false);
          toast.error(data.message);
        }
      };

      const handleplanlistResponse = (response) => {
        if (!response) {
          console.error("Empty response received");
          return;
        }
        if (response.done && Array.isArray(response.data)) {
          settableLoading(false);
          setData(response.data);
        } else {
          console.error("Invalid data format:", response);
        }
      };

      const handleUpdateResponse = (data) => {
        console.log("Response from server:", data);
        if (data.done) {
          document.getElementById("close-edit-plan").click();
          setIsLoading(false);
          reset_form();
          toast.success("Plan updated successfully!");
        } else {
          setIsLoading(false);
          toast.error(data.message);
        }
      };

      const handleDeleteResponse = (data) => {
        console.log("Response from server:", data);
        if (data.done) {
          setdeleteLoader(false);
          toast.success(data.message);
          document.getElementById("close-delete-plan").click();
        } else {
          setIsLoading(false);
          toast.error(data.message);
        }
      };

      const handleplanDetails = (details) => {
        if (details.done) {
          setplan_details(details.data);
        } else {
          setplan_details({ total: null, active: 0, inactive: 0, type: 0 });
          toast.error(details.message);
        }
      };

      const handleeditplan = (response) => {
        if (response.done) {
          setFormData({
            ...response.data,
            planModules: {
              employees: response.data.planModules.includes("employees"),
              invoices: response.data.planModules.includes("invoices"),
              reports: response.data.planModules.includes("reports"),
              contacts: response.data.planModules.includes("contacts"),
              clients: response.data.planModules.includes("clients"),
              estimates: response.data.planModules.includes("estimates"),
              goals: response.data.planModules.includes("goals"),
              deals: response.data.planModules.includes("deals"),
              projects: response.data.planModules.includes("projects"),
              payments: response.data.planModules.includes("payments"),
              assets: response.data.planModules.includes("assets"),
              leads: response.data.planModules.includes("leads"),
              tickets: response.data.planModules.includes("tickets"),
              taxes: response.data.planModules.includes("taxes"),
              activities: response.data.planModules.includes("activities"),
              pipelines: response.data.planModules.includes("pipelines"),
            },
          });
          setLogo(response.data.logo);
          console.log("Edit plans ----->", response.data);
          seteditmodelLoading(false);
          //ABC
          console.log(formData.planType);
          setResetKey((prevKey) => prevKey + 1);
        }
      };

      // Attach the event listeners
      socket.on("superadmin/packages/add-plan-response", handleAddResponse);
      socket.on(
        "superadmin/packages/update-plan-response",
        handleUpdateResponse
      );
      socket.on(
        "superadmin/packages/planlist-response",
        handleplanlistResponse
      );
      socket.on(
        "superadmin/packages/delete-plan-response",
        handleDeleteResponse
      );
      socket.on("superadmin/packages/plan-details-response", handleplanDetails);

      socket.on("superadmin/packages/get-plan-response", handleeditplan);

      // Cleanup: Remove the event listeners when the component unmounts
      return () => {
        socket.off("superadmin/packages/add-plan-response", handleAddResponse);
        socket.off(
          "superadmin/packages/update-plan-response",
          handleUpdateResponse
        );
        socket.off(
          "superadmin/packages/delete-plan-response",
          handleDeleteResponse
        );
        socket.off(
          "superadmin/packages/plan-details-response",
          handleplanDetails
        );
        socket.off(
          "superadmin/packages/planlist-response",
          handleplanlistResponse
        );
        socket.off("superadmin/packages/get-plan-response", handleeditplan);
      };
    }
  }, [socket]);

  const [formData, setFormData] = useState({
    planName: "",
    planType: null,
    planPosition: null,
    planCurrency: null,
    planCurrencytype: null,
    discountType: null,
    discount: 0,
    limitationsInvoices: 0,
    maxCustomers: 0,
    price: "",
    product: 0,
    supplier: 0,
    planModules: {
      employees: false,
      invoices: false,
      reports: false,
      contacts: false,
      clients: false,
      estimates: false,
      goals: false,
      deals: false,
      projects: false,
      payments: false,
      assets: false,
      leads: false,
      tickets: false,
      taxes: false,
      activities: false,
      pipelines: false,
    },
    accessTrial: false,
    trialDays: 0,
    isRecommended: false,
    status: null,
    description: "",
  });

  const DeletePlan = () => {
    if (deleteplan.length > 0) {
      setdeleteLoader(true);
      socket.emit("superadmin/packages/delete-plan", deleteplan);
    }
  };

  const handleImageUpload = async (event) => {
    const file = event.target.files?.[0];

    if (!file) {
      return; // No file selected
    }

    const maxSize = 4 * 1024 * 1024; // 3MB in bytes
    if (file.size > maxSize) {
      toast.error("File size must be less than 4MB.", {
        position: "top-right",
        autoClose: 3000,
        hideProgressBar: true,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
      });
      event.target.value = ""; // Clear the file input
      return;
    }

    if (
      file &&
      ["image/jpeg", "image/png", "image/jpg", "image/ico"].includes(file.type)
    ) {
      setimageupload(true);
      const uploadedUrl = await uploadImage(file);
      setLogo(uploadedUrl);
      console.log(uploadedUrl);
      setimageupload(false);
    } else {
      toast.error(`Please Upload Image file only.`, {
        position: "top-right",
        autoClose: 3000,
        hideProgressBar: true,
        closeOnClick: true,
        pauseOnHover: true,
        draggable: true,
      });
      event.target.value = "";
    }
  };

  const RemoveLogo = () => {
    setLogo(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  useEffect(() => {
    if (!formData.accessTrial) {
      setFormData((prev) => ({ ...prev, trialDays: 0 }));
    }
  }, [formData.accessTrial]);

  // View of Page

  const [plan_details, setplan_details] = useState({
    totalPlans: null,
    activePlans: null,
    inactivePlans: null,
    planTypes: null,
  });

  useEffect(() => {
    if (socket) {
      socket.emit("superadmin/packages/planlist", "All");
      socket.emit("superadmin/packages/plan-details", true);
    }
  }, [socket]);

  useEffect(() => {
    if (socket) {
      console.log("Socket changed:", socket.id || socket);
    }
  }, [socket]);

  return (
    <>
      {/* baseColor="#313131" highlightColor="#525252" */}
      <SkeletonTheme>
        {/* Page Wrapper */}
        <div className="page-wrapper">
          <div className="content">
            {/* Breadcrumb */}
            <div className="d-md-flex d-block align-items-center justify-content-between page-breadcrumb mb-3">
              <div className="my-auto mb-2">
                <h2 className="mb-1">Packages</h2>
                <nav>
                  <ol className="breadcrumb mb-0">
                    <li className="breadcrumb-item">
                      <Link to={all_routes.adminDashboard}>
                        <i className="ti ti-smart-home" />
                      </Link>
                    </li>
                    <li className="breadcrumb-item">Superadmin</li>
                    <li className="breadcrumb-item active" aria-current="page">
                      Packages List
                    </li>
                  </ol>
                </nav>
              </div>
              <div className="d-flex my-xl-auto right-content align-items-center flex-wrap ">
                <div className="me-2 mb-2">
                  <div className="d-flex align-items-center border bg-white rounded p-1 me-2 icon-list">
                    <Link
                      to="#"
                      className="btn btn-icon btn-sm active bg-primary text-white me-1"
                    >
                      <i className="ti ti-list-tree" />
                    </Link>
                  </div>
                </div>
                <div className="me-2 mb-2">
                  <div className="dropdown">
                    <Link
                      to="#"
                      className="dropdown-toggle btn btn-white d-inline-flex align-items-center"
                      data-bs-toggle="dropdown"
                    >
                      <i className="ti ti-file-export me-1" />
                      Export
                    </Link>
                    <ul className="dropdown-menu  dropdown-menu-end p-3">
                      <li>
                        <Link to="#" className="dropdown-item rounded-1">
                          <i className="ti ti-file-type-pdf me-1" />
                          Export as PDF
                        </Link>
                      </li>
                      <li>
                        <Link to="#" className="dropdown-item rounded-1">
                          <i className="ti ti-file-type-xls me-1" />
                          Export as Excel{" "}
                        </Link>
                      </li>
                    </ul>
                  </div>
                </div>
                <div className="mb-2">
                  <Link
                    to="#"
                    data-bs-toggle="modal"
                    data-bs-target="#add_plans"
                    className="btn btn-primary d-flex align-items-center"
                    onClick={reset_form}
                  >
                    <i className="ti ti-circle-plus me-2" />
                    Add Plan
                  </Link>
                </div>
                <div className="ms-2 head-icons">
                  <CollapseHeader />
                </div>
              </div>
            </div>
            {/* /Breadcrumb */}
            <div className="row">
              {/* Total Plans */}
              <div className="col-lg-3 col-md-6 d-flex">
                <div className="card flex-fill">
                  <div className="card-body d-flex align-items-center justify-content-between">
                    <div className="d-flex align-items-center overflow-hidden">
                      <div>
                        <p className="fs-12 fw-medium mb-1 text-truncate">
                          Total Plans
                        </p>
                        <h4>{plan_details.totalPlans || <Skeleton />}</h4>
                      </div>
                    </div>
                    <div>
                      <span className="avatar avatar-lg bg-primary flex-shrink-0">
                        <i className="ti ti-box fs-16" />
                      </span>
                    </div>
                  </div>
                </div>
              </div>
              {/* /Total Plans */}
              {/* Total Plans */}
              <div className="col-lg-3 col-md-6 d-flex">
                <div className="card flex-fill">
                  <div className="card-body d-flex align-items-center justify-content-between">
                    <div className="d-flex align-items-center overflow-hidden">
                      <div>
                        <p className="fs-12 fw-medium mb-1 text-truncate">
                          Active Plans
                        </p>
                        <h4>{plan_details.activePlans || <Skeleton />}</h4>
                      </div>
                    </div>
                    <div>
                      <span className="avatar avatar-lg bg-success flex-shrink-0">
                        <i className="ti ti-activity-heartbeat fs-16" />
                      </span>
                    </div>
                  </div>
                </div>
              </div>
              {/* /Total Plans */}
              {/* Inactive Plans */}
              <div className="col-lg-3 col-md-6 d-flex">
                <div className="card flex-fill">
                  <div className="card-body d-flex align-items-center justify-content-between">
                    <div className="d-flex align-items-center overflow-hidden">
                      <div>
                        <p className="fs-12 fw-medium mb-1 text-truncate">
                          Inactive Plans
                        </p>
                        <h4>{plan_details.inactivePlans || <Skeleton />}</h4>
                      </div>
                    </div>
                    <div>
                      <span className="avatar avatar-lg bg-danger flex-shrink-0">
                        <i className="ti ti-player-pause fs-16" />
                      </span>
                    </div>
                  </div>
                </div>
              </div>
              {/* /Inactive Companies */}
              {/* No of Plans  */}
              <div className="col-lg-3 col-md-6 d-flex">
                <div className="card flex-fill">
                  <div className="card-body d-flex align-items-center justify-content-between">
                    <div className="d-flex align-items-center overflow-hidden">
                      <div>
                        <p className="fs-12 fw-medium mb-1 text-truncate">
                          No of Plan Types
                        </p>
                        <h4>{plan_details.planTypes || <Skeleton />}</h4>
                      </div>
                    </div>
                    <div>
                      <span className="avatar avatar-lg bg-skyblue flex-shrink-0">
                        <i className="ti ti-mask fs-16" />
                      </span>
                    </div>
                  </div>
                </div>
              </div>
              {/* /No of Plans */}
            </div>
            <div className="card">
              <div className="card-header d-flex align-items-center justify-content-between flex-wrap row-gap-3">
                <h5>Plan List</h5>
                <div className="d-flex my-xl-auto right-content align-items-center flex-wrap row-gap-3">
                  {deleteplan.length > 1 && (
                    <div className="me-3">
                      <button
                        type="button"
                        data-bs-toggle="modal"
                        data-bs-target="#delete_modal"
                        className="btn btn-primary me-2"
                      >
                        Delete Selected
                      </button>
                    </div>
                  )}

                  <div className="me-3">
                    <div className="input-icon-end position-relative">
                      <PredefinedDateRanges
                        value={filters.dateRange}
                        onChange={(range) => {
                          setFilters((prev) => ({
                            ...prev,
                            dateRange: {
                              start: range.start,
                              end: range.end,
                            },
                          }));
                        }}
                      />

                      <span className="input-icon-addon">
                        <i className="ti ti-chevron-down" />
                      </span>
                    </div>
                  </div>
                  <div className="dropdown me-3">
                    <button
                      className="dropdown-toggle btn btn-white d-inline-flex align-items-center"
                      data-bs-toggle="dropdown"
                      aria-expanded="false"
                    >
                      {filters.planType ? filters.planType : "Select Plan"}
                    </button>
                    <ul className="dropdown-menu dropdown-menu-end p-3">
                      <li>
                        <button
                          className="dropdown-item rounded-1"
                          onClick={() => {
                            setFilters({
                              ...filters,
                              planType: null,
                            });
                          }}
                        >
                          Select Plan
                        </button>
                      </li>
                      <li>
                        <button
                          className="dropdown-item rounded-1"
                          onClick={() => {
                            setFilters({
                              ...filters,
                              planType: "Monthly",
                            });
                          }}
                        >
                          Monthly
                        </button>
                      </li>
                      <li>
                        <button
                          className="dropdown-item rounded-1"
                          onClick={() => {
                            setFilters({
                              ...filters,
                              planType: "Yearly",
                            });
                          }}
                        >
                          Yearly
                        </button>
                      </li>
                    </ul>
                  </div>
                  <div className="dropdown me-3">
                    <button
                      className="dropdown-toggle btn btn-white d-inline-flex align-items-center"
                      data-bs-toggle="dropdown"
                      aria-expanded="false"
                    >
                      {filters.status ? filters.status : "Select Status"}
                    </button>
                    <ul className="dropdown-menu dropdown-menu-end p-3">
                      <li>
                        <button
                          className="dropdown-item rounded-1"
                          onClick={() => {
                            setFilters({ ...filters, status: null });
                          }}
                        >
                          Select Status
                        </button>
                      </li>
                      <li>
                        <button
                          className="dropdown-item rounded-1"
                          onClick={() => {
                            setFilters({ ...filters, status: "Active" });
                          }}
                        >
                          Active
                        </button>
                      </li>
                      <li>
                        <button
                          className="dropdown-item rounded-1"
                          onClick={() => {
                            setFilters({ ...filters, status: "Inactive" });
                          }}
                        >
                          Inactive
                        </button>
                      </li>
                    </ul>
                  </div>
                </div>
              </div>
              <div className="card-body p-0">
                :
                {tableLoading ? (
                  // Loading Animation
                  <div className="d-flex justify-content-center mb-4">
                    <div className="spinner-border" role="status">
                      <span className="sr-only">Loading...</span>
                    </div>
                  </div>
                ) : (
                  <Table
                    dataSource={tempfiltereddata ?? Data} // Use filtered data if available, otherwise fallback to original
                    columns={columns}
                    rowId="planid"
                    Selection={true}
                    onChange={(selectedid) => {
                      console.log("Selected IF", selectedid);
                      setdeleteplan(selectedid);
                    }}
                  />
                )}
              </div>
            </div>
          </div>
          <div className="footer d-sm-flex align-items-center justify-content-between border-top bg-white p-3">
            <p className="mb-0">2014 - 2025 © SmartHR.</p>
            <p>
              Designed &amp; Developed By{" "}
              <Link to="amasQIS.ai" className="text-primary">
                amasQIS.ai
              </Link>
            </p>
          </div>
        </div>
        {/* /Page Wrapper */}
        {/* Add Plan */}
        <div className="modal fade" id="add_plans">
          <div className="modal-dialog modal-dialog-centered modal-lg">
            <div className="modal-content">
              <div className="modal-header">
                <h4 className="modal-title">Add New Plan</h4>
                <button
                  type="button"
                  className="btn-close custom-btn-close"
                  data-bs-dismiss="modal"
                  id="close-model"
                  aria-label="Close"
                >
                  <i className="ti ti-x" />
                </button>
              </div>
              <form onSubmit={handleSubmit} autoComplete="off">
                <div className="modal-body pb-0">
                  <div className="row">
                    <div className="col-md-12">
                      <div className="d-flex align-items-center flex-wrap row-gap-3 bg-light w-100 rounded p-3 mb-4">
                        <div className="d-flex align-items-center justify-content-center avatar avatar-xxl rounded-circle border border-dashed me-2 flex-shrink-0 text-dark frames">
                          {logo ? (
                            <img
                              src={logo}
                              alt="Uploaded Logo"
                              className="rounded-circle"
                              style={{
                                width: "100%",
                                height: "100%",
                                objectFit: "cover",
                              }}
                            />
                          ) : imageupload ? (
                            <div
                              className="spinner-border text-primary"
                              role="status"
                            >
                              <span className="visually-hidden">
                                Uploading...
                              </span>
                            </div>
                          ) : (
                            <ImageWithBasePath
                              src="assets/img/profiles/avatar-30.jpg"
                              alt="img"
                              className="rounded-circle"
                            />
                          )}
                        </div>
                        <div className="profile-upload">
                          <div className="mb-2">
                            <h6 className="mb-1">Upload Profile Image</h6>
                            <p className="fs-12">Image should be below 4 mb</p>
                          </div>
                          <div className="profile-uploader d-flex align-items-center">
                            <div className="drag-upload-btn btn btn-sm btn-primary me-2">
                              {logo ? "Change" : "Upload"}
                              <input
                                required
                                type="file"
                                className="form-control image-sign"
                                accept=".png,.jpeg,.jpg,.ico"
                                ref={fileInputRef}
                                onChange={handleImageUpload}
                              />
                            </div>
                            {logo && (
                              <Link
                                to="#"
                                onClick={RemoveLogo}
                                className="btn btn-light btn-sm"
                              >
                                Remove
                              </Link>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3 ">
                        <label className="form-label">
                          Plan Name<span className="text-danger"> *</span>
                        </label>

                        <input
                          type="text"
                          className="form-control"
                          name="planName"
                          placeholder="Enter a plan name"
                          value={formData.planName}
                          onChange={handleInputChange}
                          required
                          maxLength={100}
                          autocomplete="none"
                          // Set reasonable limits
                        />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3 ">
                        <label className="form-label">
                          Plan Type<span className="text-danger"> *</span>
                        </label>
                        <CommonSelect
                          key={resetKey}
                          className="select"
                          options={planType}
                          defaultValue={formData.planType}
                          onChange={(selectedOption) =>
                            handleSelectChange("planType", selectedOption)
                          }
                        />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3 ">
                        <label className="form-label">
                          Plan Position<span className="text-danger"> *</span>
                        </label>
                        <CommonSelect
                          key={resetKey}
                          className="select"
                          options={planPosition}
                          defaultValue={formData.planPosition}
                          onChange={(selectedOption) =>
                            handleSelectChange("planPosition", selectedOption)
                          }
                        />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3 ">
                        <label className="form-label">
                          Plan Currency<span className="text-danger"> *</span>
                        </label>
                        <CommonSelect
                          key={resetKey}
                          className="select"
                          options={currency}
                          defaultValue={formData.planCurrency}
                          onChange={(selectedOption) =>
                            handleSelectChange("planCurrency", selectedOption)
                          }
                        />
                      </div>
                    </div>
                    <div className="col-md-6">
                      <div className="mb-3">
                        <div className="d-flex justify-content-between">
                          <label className="form-label">
                            Plan Currency Type
                            <span className="text-danger"> *</span>
                          </label>
                          <span className="text-primary">
                            <i className="fa-solid fa-circle-exclamation me-2" />
                            Set 0 for free
                          </span>
                        </div>
                        <CommonSelect
                          key={resetKey}
                          className="select"
                          options={plancurrency}
                          defaultValue={formData.planCurrencytype}
                          onChange={(selectedOption) =>
                            handleSelectChange(
                              "planCurrencytype",
                              selectedOption
                            )
                          }
                        />
                      </div>
                    </div>
                    <div className="col-md-3">
                      <div className="mb-3 ">
                        <label className="form-label">
                          Discount Type<span className="text-danger"> *</span>
                        </label>
                        <div className="pass-group">
                          <CommonSelect
                            key={resetKey}
                            className="select"
                            options={discountType}
                            defaultValue={formData.discountType}
                            onChange={(selectedOption) =>
                              handleSelectChange("discountType", selectedOption)
                            }
                          />
                        </div>
                      </div>
                    </div>
                    <div className="col-md-3">
                      <div className="mb-3 ">
                        <label className="form-label">
                          Discount<span className="text-danger"> *</span>
                        </label>
                        <div className="pass-group">
                          <input
                            required
                            type="number"
                            min={0}
                            className="form-control"
                            name="discount"
                            value={formData.discount}
                            onChange={handleInputChange}
                          />
                        </div>
                      </div>
                    </div>
                    <div className="col-lg-3">
                      <div className="mb-3">
                        <label className="form-label">
                          Limitations Invoices
                        </label>
                        <input
                          type="number"
                          min={0}
                          className="form-control"
                          name="limitationsInvoices"
                          value={formData.limitationsInvoices}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    <div className="col-lg-3">
                      <div className="mb-3">
                        <label className="form-label">Max Customers</label>
                        <input
                          type="number"
                          min={0}
                          className="form-control"
                          name="maxCustomers"
                          value={formData.maxCustomers}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    <div className="col-lg-3">
                      <div className="mb-3">
                        <label className="form-label">Product</label>
                        <input
                          type="number"
                          min={0}
                          className="form-control"
                          name="product"
                          value={formData.product}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    <div className="col-lg-3">
                      <div className="mb-3">
                        <label className="form-label">Supplier</label>
                        <input
                          type="number"
                          min={0}
                          className="form-control"
                          name="supplier"
                          value={formData.supplier}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    <div className="col-lg-3">
                      <div className="mb-3">
                        <label className="form-label">
                          Price <span className="text-danger"> *</span>
                        </label>
                        <input
                          type="number"
                          min={0}
                          className="form-control"
                          name="price"
                          required
                          value={formData.price}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                    <div className="col-lg-12">
                      <div className="d-flex align-items-center justify-content-between mb-3">
                        <h6>Plan Modules</h6>
                        <div className="form-check d-flex align-items-center">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="selectAll"
                              id="select-all-btn"
                              onChange={(e) => {
                                const isChecked = e.target.checked;
                                setFormData((prevState) => ({
                                  ...prevState,
                                  planModules: {
                                    employees: isChecked,
                                    invoices: isChecked,
                                    reports: isChecked,
                                    contacts: isChecked,
                                    clients: isChecked,
                                    estimates: isChecked,
                                    goals: isChecked,
                                    deals: isChecked,
                                    projects: isChecked,
                                    payments: isChecked,
                                    assets: isChecked,
                                    leads: isChecked,
                                    tickets: isChecked,
                                    taxes: isChecked,
                                    activities: isChecked,
                                    pipelines: isChecked,
                                  },
                                }));
                              }}
                            />
                            Select All
                          </label>
                        </div>
                      </div>
                    </div>
                    <div className="row">
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="employees"
                              checked={formData.planModules.employees}
                              onChange={handlePlanModulesChange}
                            />
                            Employees
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="invoices"
                              checked={formData.planModules.invoices}
                              onChange={handlePlanModulesChange}
                            />
                            Invoices
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="reports"
                              checked={formData.planModules.reports}
                              onChange={handlePlanModulesChange}
                            />
                            Reports
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="contacts"
                              checked={formData.planModules.contacts}
                              onChange={handlePlanModulesChange}
                            />
                            Contacts
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="clients"
                              checked={formData.planModules.clients}
                              onChange={handlePlanModulesChange}
                            />
                            Clients
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="estimates"
                              checked={formData.planModules.estimates}
                              onChange={handlePlanModulesChange}
                            />
                            Estimates
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="goals"
                              checked={formData.planModules.goals}
                              onChange={handlePlanModulesChange}
                            />
                            Goals
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="deals"
                              checked={formData.planModules.deals}
                              onChange={handlePlanModulesChange}
                            />
                            Deals
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="projects"
                              checked={formData.planModules.projects}
                              onChange={handlePlanModulesChange}
                            />
                            Projects
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="payments"
                              checked={formData.planModules.payments}
                              onChange={handlePlanModulesChange}
                            />
                            Payments
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="assets"
                              checked={formData.planModules.assets}
                              onChange={handlePlanModulesChange}
                            />
                            Assets
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="leads"
                              checked={formData.planModules.leads}
                              onChange={handlePlanModulesChange}
                            />
                            Leads
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="tickets"
                              checked={formData.planModules.tickets}
                              onChange={handlePlanModulesChange}
                            />
                            Tickets
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="taxes"
                              checked={formData.planModules.taxes}
                              onChange={handlePlanModulesChange}
                            />
                            Taxes
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="activities"
                              checked={formData.planModules.activities}
                              onChange={handlePlanModulesChange}
                            />
                            Activities
                          </label>
                        </div>
                      </div>
                      <div className="col-lg-3 col-sm-6">
                        <div className="form-check d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 text-dark fw-medium">
                            <input
                              className="form-check-input"
                              type="checkbox"
                              name="pipelines"
                              checked={formData.planModules.pipelines}
                              onChange={handlePlanModulesChange}
                            />
                            Pipelines
                          </label>
                        </div>
                      </div>
                      <div className="col-md-6">
                        <div className="d-flex align-items-center mb-3">
                          <label className="form-check-label mt-0 me-2 text-dark fw-medium">
                            Access Trial
                          </label>
                          <div className="form-check form-switch me-2">
                            <input
                              className="form-check-input me-2"
                              type="checkbox"
                              role="switch"
                              name="accessTrial"
                              checked={formData.accessTrial}
                              onChange={handleInputChange}
                            />
                          </div>
                        </div>
                      </div>
                    </div>
                    <div className="row align-items-center gx-3">
                      <div className="col-md-4">
                        <div className="d-flex align-items-center mb-3">
                          <div className="flex-fill">
                            <label className="form-label">Trial Days</label>
                            <input
                              disabled={formData.accessTrial ? false : true}
                              type="number"
                              min={0}
                              className="form-control"
                              name="trialDays"
                              value={formData.trialDays}
                              onChange={handleInputChange}
                            />
                          </div>
                        </div>
                      </div>
                      <div className="col-md-3">
                        <div className="d-block align-items-center ms-3">
                          <label className="form-check-label mt-0 me-2 text-dark">
                            Is Recommended
                          </label>
                          <div className="form-check form-switch me-2">
                            <input
                              className="form-check-input me-2"
                              type="checkbox"
                              role="switch"
                              name="isRecommended"
                              checked={formData.isRecommended}
                              onChange={handleInputChange}
                            />
                          </div>
                        </div>
                      </div>
                      <div className="col-md-5">
                        <div className="mb-3 ">
                          <label className="form-label">
                            Status<span className="text-danger"> *</span>
                          </label>
                          <CommonSelect
                            key={resetKey}
                            className="select"
                            options={status}
                            defaultValue={formData.status}
                            onChange={(selectedOption) =>
                              handleSelectChange("status", selectedOption)
                            }
                          />
                        </div>
                      </div>
                    </div>
                    <div className="col-md-12">
                      <div className="mb-3">
                        <label className="form-label">Description</label>
                        <textarea
                          className="form-control"
                          name="description"
                          value={formData.description}
                          onChange={handleInputChange}
                        />
                      </div>
                    </div>
                  </div>
                </div>
                <div className="modal-footer">
                  <button
                    type="button"
                    className="btn btn-light me-2"
                    onClick={reset_form}
                    data-bs-dismiss="modal"
                    id="close-add-plan"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    // data-bs-dismiss="modal"
                    className="btn btn-primary"
                    disabled={isLoading} // Disable the button when loading
                  >
                    {isLoading ? (
                      <>
                        <span
                          className="spinner-border spinner-border-sm me-2"
                          role="status"
                          aria-hidden="true"
                        />
                        Adding...
                      </>
                    ) : (
                      "Add Plan"
                    )}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
        {/* /Add Plan */}

        {/* Delete Plan */}
        <div className="modal fade" id="delete_modal">
          <div className="modal-dialog modal-dialog-centered">
            <div className="modal-content">
              <div className="modal-body text-center">
                <span className="avatar avatar-xl bg-transparent-danger text-danger mb-3">
                  <i className="ti ti-trash-x fs-36" />
                </span>
                <h4 className="mb-1">Confirm Delete</h4>

                <p className="mb-3">
                  {deleteplan.length > 1 &&
                    `You want to delete all the marked items, this cant be undone
                    once you delete.`}
                </p>

                <div className="d-flex justify-content-center">
                  <Link
                    to="#"
                    className="btn btn-light me-3"
                    data-bs-dismiss="modal"
                    id="close-delete-plan"
                    onClick={() => {
                      setdeleteplan([]);
                    }}
                  >
                    Cancel
                  </Link>
                  {deleteLoader ? (
                    <Link
                      to="#"
                      data-bs-dismiss="modal"
                      className="btn btn-danger"
                      onClick={DeletePlan}
                    >
                      <span
                        className="spinner-border spinner-border-sm me-2"
                        role="status"
                        aria-hidden="true"
                      />
                      Deleting...
                    </Link>
                  ) : (
                    <Link
                      to="#"
                      data-bs-dismiss="modal"
                      className="btn btn-danger"
                      onClick={DeletePlan}
                    >
                      Yes, Delete
                    </Link>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
        {/* Edit Plan */}
        <div className="modal fade" id="edit_plans">
          <div className="modal-dialog modal-dialog-centered modal-lg">
            <div className="modal-content">
              <div className="modal-header">
                <h4 className="modal-title">Edit New Plan</h4>
                <button
                  type="button"
                  className="btn-close custom-btn-close"
                  data-bs-dismiss="modal"
                  id="close-model-edit"
                  aria-label="Close"
                >
                  <i className="ti ti-x" />
                </button>
              </div>
              {editmodelLoading ? (
                <div className="card-body d-flex justify-content-center align-items-center">
                  <div className="d-flex justify-content-center align-items-center mb-4">
                    <div className="spinner-border" role="status">
                      <span className="visually-hidden">Loading...</span>
                    </div>
                  </div>
                </div>
              ) : (
                <form onSubmit={handleEditSubmit} autoComplete="off">
                  <div className="modal-body pb-0">
                    <div className="row">
                      <div className="col-md-12">
                        <div className="d-flex align-items-center flex-wrap row-gap-3 bg-light w-100 rounded p-3 mb-4">
                          <div className="d-flex align-items-center justify-content-center avatar avatar-xxl rounded-circle border border-dashed me-2 flex-shrink-0 text-dark frames">
                            {logo ? (
                              <img
                                src={logo}
                                alt="Uploaded Logo"
                                className="rounded-circle"
                                style={{
                                  width: "100%",
                                  height: "100%",
                                  objectFit: "cover",
                                }}
                              />
                            ) : imageupload ? (
                              <div
                                className="spinner-border text-primary"
                                role="status"
                              >
                                <span className="visually-hidden">
                                  Uploading...
                                </span>
                              </div>
                            ) : (
                              <ImageWithBasePath
                                src="assets/img/profiles/avatar-30.jpg"
                                alt="img"
                                className="rounded-circle"
                              />
                            )}
                          </div>
                          <div className="profile-upload">
                            <div className="mb-2">
                              <h6 className="mb-1">Upload Profile Image</h6>
                              <p className="fs-12">
                                Image should be below 4 mb
                              </p>
                            </div>
                            <div className="profile-uploader d-flex align-items-center">
                              <div className="drag-upload-btn btn btn-sm btn-primary me-2">
                                {logo ? "Change" : "Upload"}
                                <input
                                  type="file"
                                  className="form-control image-sign"
                                  accept=".png,.jpeg,.jpg,.ico"
                                  ref={fileInputRef}
                                  onChange={handleImageUpload}
                                />
                              </div>
                              {logo && (
                                <Link
                                  to="#"
                                  onClick={RemoveLogo}
                                  className="btn btn-light btn-sm"
                                >
                                  Remove
                                </Link>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="col-md-6">
                        <div className="mb-3 ">
                          <label className="form-label">
                            Plan Name<span className="text-danger"> *</span>
                          </label>

                          <input
                            type="text"
                            className="form-control"
                            name="planName"
                            placeholder="Enter a plan name"
                            value={formData.planName}
                            onChange={handleInputChange}
                            required
                            maxLength={100}
                            autocomplete="none"
                            // Set reasonable limits
                          />
                        </div>
                      </div>
                      <div className="col-md-6">
                        <div className="mb-3 ">
                          <label className="form-label">
                            Plan Type<span className="text-danger"> *</span>
                          </label>
                          <CommonSelect
                            key={resetKey}
                            className="select"
                            options={planType}
                            defaultValue={formData.planType}
                            onChange={(selectedOption) =>
                              handleSelectChange("planType", selectedOption)
                            }
                          />
                        </div>
                      </div>
                      <div className="col-md-6">
                        <div className="mb-3 ">
                          <label className="form-label">
                            Plan Position<span className="text-danger"> *</span>
                          </label>
                          <CommonSelect
                            key={resetKey}
                            className="select"
                            options={planPosition}
                            defaultValue={formData.planPosition}
                            onChange={(selectedOption) =>
                              handleSelectChange("planPosition", selectedOption)
                            }
                          />
                        </div>
                      </div>
                      <div className="col-md-6">
                        <div className="mb-3 ">
                          <label className="form-label">
                            Plan Currency<span className="text-danger"> *</span>
                          </label>
                          <CommonSelect
                            key={resetKey}
                            className="select"
                            options={currency}
                            defaultValue={formData.planCurrency}
                            onChange={(selectedOption) =>
                              handleSelectChange("planCurrency", selectedOption)
                            }
                          />
                        </div>
                      </div>
                      <div className="col-md-6">
                        <div className="mb-3">
                          <div className="d-flex justify-content-between">
                            <label className="form-label">
                              Plan Currency Type
                              <span className="text-danger"> *</span>
                            </label>
                            <span className="text-primary">
                              <i className="fa-solid fa-circle-exclamation me-2" />
                              Set 0 for free
                            </span>
                          </div>
                          <CommonSelect
                            key={resetKey}
                            className="select"
                            options={plancurrency}
                            defaultValue={formData.planCurrencytype}
                            onChange={(selectedOption) =>
                              handleSelectChange(
                                "planCurrencytype",
                                selectedOption
                              )
                            }
                          />
                        </div>
                      </div>
                      <div className="col-md-3">
                        <div className="mb-3 ">
                          <label className="form-label">
                            Discount Type<span className="text-danger"> *</span>
                          </label>
                          <div className="pass-group">
                            <CommonSelect
                              key={resetKey}
                              className="select"
                              options={discountType}
                              defaultValue={formData.discountType}
                              onChange={(selectedOption) =>
                                handleSelectChange(
                                  "discountType",
                                  selectedOption
                                )
                              }
                            />
                          </div>
                        </div>
                      </div>
                      <div className="col-md-3">
                        <div className="mb-3 ">
                          <label className="form-label">
                            Discount<span className="text-danger"> *</span>
                          </label>
                          <div className="pass-group">
                            <input
                              required
                              type="number"
                              min={0}
                              className="form-control"
                              name="discount"
                              value={formData.discount}
                              onChange={handleInputChange}
                            />
                          </div>
                        </div>
                      </div>
                      <div className="col-lg-3">
                        <div className="mb-3">
                          <label className="form-label">
                            Limitations Invoices
                          </label>
                          <input
                            type="number"
                            min={0}
                            className="form-control"
                            name="limitationsInvoices"
                            value={formData.limitationsInvoices}
                            onChange={handleInputChange}
                          />
                        </div>
                      </div>
                      <div className="col-lg-3">
                        <div className="mb-3">
                          <label className="form-label">Max Customers</label>
                          <input
                            type="number"
                            min={0}
                            className="form-control"
                            name="maxCustomers"
                            value={formData.maxCustomers}
                            onChange={handleInputChange}
                          />
                        </div>
                      </div>
                      <div className="col-lg-3">
                        <div className="mb-3">
                          <label className="form-label">Product</label>
                          <input
                            type="number"
                            min={0}
                            className="form-control"
                            name="product"
                            value={formData.product}
                            onChange={handleInputChange}
                          />
                        </div>
                      </div>
                      <div className="col-lg-3">
                        <div className="mb-3">
                          <label className="form-label">Supplier</label>
                          <input
                            type="number"
                            min={0}
                            className="form-control"
                            name="supplier"
                            value={formData.supplier}
                            onChange={handleInputChange}
                          />
                        </div>
                      </div>
                      <div className="col-lg-3">
                        <div className="mb-3">
                          <label className="form-label">
                            Price <span className="text-danger"> *</span>
                          </label>
                          <input
                            type="number"
                            min={0}
                            className="form-control"
                            name="price"
                            required
                            value={formData.price}
                            onChange={handleInputChange}
                          />
                        </div>
                      </div>
                      <div className="col-lg-12">
                        <div className="d-flex align-items-center justify-content-between mb-3">
                          <h6>Plan Modules</h6>
                          <div className="form-check d-flex align-items-center">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="selectAll"
                                id="select-all-btn"
                                onChange={(e) => {
                                  const isChecked = e.target.checked;
                                  setFormData((prevState) => ({
                                    ...prevState,
                                    planModules: {
                                      employees: isChecked,
                                      invoices: isChecked,
                                      reports: isChecked,
                                      contacts: isChecked,
                                      clients: isChecked,
                                      estimates: isChecked,
                                      goals: isChecked,
                                      deals: isChecked,
                                      projects: isChecked,
                                      payments: isChecked,
                                      assets: isChecked,
                                      leads: isChecked,
                                      tickets: isChecked,
                                      taxes: isChecked,
                                      activities: isChecked,
                                      pipelines: isChecked,
                                    },
                                  }));
                                }}
                              />
                              Select All
                            </label>
                          </div>
                        </div>
                      </div>
                      <div className="row">
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="employees"
                                checked={formData.planModules.employees}
                                onChange={handlePlanModulesChange}
                              />
                              Employees
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="invoices"
                                checked={formData.planModules.invoices}
                                onChange={handlePlanModulesChange}
                              />
                              Invoices
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="reports"
                                checked={formData.planModules.reports}
                                onChange={handlePlanModulesChange}
                              />
                              Reports
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="contacts"
                                checked={formData.planModules.contacts}
                                onChange={handlePlanModulesChange}
                              />
                              Contacts
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="clients"
                                checked={formData.planModules.clients}
                                onChange={handlePlanModulesChange}
                              />
                              Clients
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="estimates"
                                checked={formData.planModules.estimates}
                                onChange={handlePlanModulesChange}
                              />
                              Estimates
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="goals"
                                checked={formData.planModules.goals}
                                onChange={handlePlanModulesChange}
                              />
                              Goals
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="deals"
                                checked={formData.planModules.deals}
                                onChange={handlePlanModulesChange}
                              />
                              Deals
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="projects"
                                checked={formData.planModules.projects}
                                onChange={handlePlanModulesChange}
                              />
                              Projects
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="payments"
                                checked={formData.planModules.payments}
                                onChange={handlePlanModulesChange}
                              />
                              Payments
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="assets"
                                checked={formData.planModules.assets}
                                onChange={handlePlanModulesChange}
                              />
                              Assets
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="leads"
                                checked={formData.planModules.leads}
                                onChange={handlePlanModulesChange}
                              />
                              Leads
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="tickets"
                                checked={formData.planModules.tickets}
                                onChange={handlePlanModulesChange}
                              />
                              Tickets
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="taxes"
                                checked={formData.planModules.taxes}
                                onChange={handlePlanModulesChange}
                              />
                              Taxes
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="activities"
                                checked={formData.planModules.activities}
                                onChange={handlePlanModulesChange}
                              />
                              Activities
                            </label>
                          </div>
                        </div>
                        <div className="col-lg-3 col-sm-6">
                          <div className="form-check d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 text-dark fw-medium">
                              <input
                                className="form-check-input"
                                type="checkbox"
                                name="pipelines"
                                checked={formData.planModules.pipelines}
                                onChange={handlePlanModulesChange}
                              />
                              Pipelines
                            </label>
                          </div>
                        </div>
                        <div className="col-md-6">
                          <div className="d-flex align-items-center mb-3">
                            <label className="form-check-label mt-0 me-2 text-dark fw-medium">
                              Access Trial
                            </label>
                            <div className="form-check form-switch me-2">
                              <input
                                className="form-check-input me-2"
                                type="checkbox"
                                role="switch"
                                name="accessTrial"
                                checked={formData.accessTrial}
                                onChange={handleInputChange}
                              />
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="row align-items-center gx-3">
                        <div className="col-md-4">
                          <div className="d-flex align-items-center mb-3">
                            <div className="flex-fill">
                              <label className="form-label">Trial Days</label>
                              <input
                                disabled={formData.accessTrial ? false : true}
                                type="number"
                                min={0}
                                className="form-control"
                                name="trialDays"
                                value={formData.trialDays}
                                onChange={handleInputChange}
                              />
                            </div>
                          </div>
                        </div>
                        <div className="col-md-3">
                          <div className="d-block align-items-center ms-3">
                            <label className="form-check-label mt-0 me-2 text-dark">
                              Is Recommended
                            </label>
                            <div className="form-check form-switch me-2">
                              <input
                                className="form-check-input me-2"
                                type="checkbox"
                                role="switch"
                                name="isRecommended"
                                checked={formData.isRecommended}
                                onChange={handleInputChange}
                              />
                            </div>
                          </div>
                        </div>
                        <div className="col-md-5">
                          <div className="mb-3 ">
                            <label className="form-label">
                              Status<span className="text-danger"> *</span>
                            </label>
                            <CommonSelect
                              key={resetKey}
                              className="select"
                              options={status}
                              defaultValue={formData.status}
                              onChange={(selectedOption) =>
                                handleSelectChange("status", selectedOption)
                              }
                            />
                          </div>
                        </div>
                      </div>
                      <div className="col-md-12">
                        <div className="mb-3">
                          <label className="form-label">Description</label>
                          <textarea
                            className="form-control"
                            name="description"
                            value={formData.description}
                            onChange={handleInputChange}
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                  <div className="modal-footer">
                    <button
                      type="button"
                      className="btn btn-light me-2"
                      onClick={reset_form}
                      id="close-edit-plan"
                      data-bs-dismiss="modal"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      // data-bs-dismiss="modal"
                      className="btn btn-primary"
                      disabled={isLoading} // Disable the button when loading
                    >
                      {isLoading ? (
                        <>
                          <span
                            className="spinner-border spinner-border-sm me-2"
                            role="status"
                            aria-hidden="true"
                          />
                          Updating...
                        </>
                      ) : (
                        "Update Plan"
                      )}
                    </button>
                  </div>
                </form>
              )}
            </div>
          </div>
        </div>
        {/* /Edit Plan */}
        <ToastContainer />
      </SkeletonTheme>
    </>
  );
};

export default Packages;
