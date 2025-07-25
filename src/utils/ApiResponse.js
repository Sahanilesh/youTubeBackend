class ApiResponse{
    constructor(
        statsCode,
        data,
        message="Success"
    ){
        this.statsCode = statsCode;
        this.data = data;
        this.message = message;
        this.success = statsCode < 400;
    }
}